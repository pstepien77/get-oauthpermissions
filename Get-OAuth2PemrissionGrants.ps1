# Check if required AzureAD PS module is loaded
if (Get-Module -Name AzureAD) {
    Write-Host "AzureAD PowerShell Module loaded.`n" -ForegroundColor Green
  } elseif (Get-Module -Name AzureADPreview) {
    Write-Host "AzureAD PowerShell Module loaded.`n" -ForegroundColor Green
  } else {
    Write-Host "Required AzureAD or AzureADPreview PowerShell module is not loaded. Hard Stop!`n" -ForegroundColor Red
    Exit 1
  }

  # Verify connectivity to Azure AD
  try {
    $TenantId = (Get-AzureADTenantDetail).ObjectId
  } catch [Microsoft.Open.Azure.AD.CommonLibrary.AadNeedAuthenticationException] { # hard stop - not connected to AAD
    Write-Host "You're not connected to target Azure tenant. Hard Stop!`n" -ForegroundColor Red
    Exit 1
  }

  $targetDomain = (Get-AzureADCurrentSessionInfo).TenantDomain
  $DateTimeStamp = Get-Date -F yyyyMMddHHmmss
  $outFile = "OAuthGrants_" + $targetDomain + "_" + $DateTimeStamp + ".csv"

  # isAdminConsent function
  function isAdminConsentReq($scopes, $permissions) {
    foreach ($scope in $scopes) {
      foreach ($perm in $permissions) {
        if ($scope -eq $perm.Value) {
          if ($perm.Type -eq "Admin") {
            return 1
          }
        }
      }
    }
  }


  Write-Host "* Processing Delegated grants ..." -ForegroundColor Green

  $allAPIs = $null
  $hashOAuth2Permissions = @{}
  ([XML](Get-Content .\APIConfig.xml)).APIList.ChildNodes | Out-GridView -PassThru  -Title 'Select target APIs' | ForEach-Object {
      $currentAPIobj = Get-AzureADServicePrincipal -Filter "AppId eq '$($_.AppId)'"
      $hashOAuth2Permissions.Add($currentAPIobj.ObjectId, $currentAPIobj.OAuth2Permissions) | Out-Null
      $currentAPIName = $_.DisplayName
      Write-Host "** Searching for delegated $currentAPIName grants ..." -ForegroundColor Green
      $allGrants += Get-AzureADOAuth2PermissionGrant -All 1 | Where-Object { $_.ResourceId -eq $currentAPIobj.objectID}
      $totalDelegatedCount = $allGrants.Count
  }


  Write-Host "*** Total number of delegated grants from all selected APIs : $totalDelegatedCount" -ForegroundColor Green

  if ($totalDelegatedCount -eq 0) {
    Write-Host "No delegated grants detected - nothing to process."
  } else {
    $processedDelegatedGrants = 0

    $allGrants | ForEach-Object {
      $processedDelegatedGrants++
      [int]$intDelegatedBar = [Math]::Round(([int]$processedDelegatedGrants / [int]$totalDelegatedCount) * 100)
      Write-Progress -Activity "Gathering information about delegated grants ..." -Status "$intDelegatedBar% Complete" -PercentComplete $intDelegatedBar

        if ($_.ConsentType -eq "AllPrincipals") {

        $adminConsentReq = 0

        $adminConsentReq = isAdminConsentReq $_.Scope.trim().split(" ") $hashOAuth2Permissions.Item($_.ResourceId)
        # If the adminConsentReq flag is set or we are processing all permissions, continue processing the grant

        if ($allPermissions -or $adminConsentReq -eq 1) {
          # Get the Client (calling) SP and the Resource (API) SP that the grant applies to
          $clientSP = Get-AzureADServicePrincipal -ObjectId $_.ClientId
          $resourceSP = Get-AzureADServicePrincipal -ObjectId $_.ResourceId

          $objOut = New-Object -TypeName psobject
          $objOut | Add-Member -MemberType NoteProperty -Name ClientSPObjectId -Value $_.ClientId
          $objOut | Add-Member -MemberType NoteProperty -Name ClientSPDisplayName -Value $clientSP.DisplayName
          $objOut | Add-Member -MemberType NoteProperty -Name ConsentType -Value "Delegated (AllPrincipals)"
          $objOut | Add-Member -MemberType NoteProperty -Name ResourceSPObjectId -Value $_.ResourceId
          $objOut | Add-Member -MemberType NoteProperty -Name ResourceSPName -Value $resourceSP.AppDisplayName
          $objOut | Add-Member -MemberType NoteProperty -Name Scope -Value $_.Scope

          Select-Object -InputObject $objOut -Property `
          ClientSPObjectId, `
          ClientSPDisplayName, `
          ConsentType, `
          ResourceSPObjectId, `
          ResourceSPName, `
          Scope | Export-Csv -NoTypeInformation -append $outFile
        }
      }
    }
}

Write-Host "`n* Processing Application grants ..." -ForegroundColor Green
$processedApplicationGrants = 0

$allServicePrincipals = Get-AzureADServicePrincipal -Top 100 -Filter "ServicePrincipalType eq 'Application'"
#$allServicePrincipals = Get-AzureADServicePrincipal -All $true -Filter "ServicePrincipalType eq 'Application'"
Write-Host "** Searching for all Application service principals ..." -ForegroundColor Green
$totalApplicationCount = $allServicePrincipals.Count

Write-Host "*** Total number of Application Service Principals to process : $totalDelegatedCount" -ForegroundColor Green
#$allServicePrincipals | ForEach-Object {
foreach ($servicePrincipal in $allServicePrincipals) {

    $processedApplicationGrants++
    [int]$intApplicationBar = [Math]::Round(([int]$processedApplicationGrants / [int]$totalApplicationCount) * 100)
    Write-Progress -Activity "Gathering information about application grants ..." -Status "$intApplicationBar% Complete" -PercentComplete $intApplicationBar


    Get-AzureADServiceAppRoleAssignedTo -ObjectId $servicePrincipal.ObjectId  -All $true `
    | Where-Object { $_.PrincipalType -eq "ServicePrincipal" -and $_.ResourceId -in $hashOAuth2Permissions.keys} | ForEach-Object {
        $assignment = $_

        $client = Get-AzureADObjectByObjectId -ObjectId $assignment.PrincipalId
        $resource = Get-AzureADObjectByObjectId -ObjectId $assignment.ResourceId
        $appRole = $resource.AppRoles | Where-Object { $_.Id -eq $assignment.Id }


        $objOut = New-Object -TypeName psobject
        $objOut | Add-Member -MemberType NoteProperty -Name ClientSPObjectId -Value $assignment.PrincipalId
        $objOut | Add-Member -MemberType NoteProperty -Name ClientSPDisplayName -Value $client.DisplayName
        $objOut | Add-Member -MemberType NoteProperty -Name ConsentType -Value "Application"
        $objOut | Add-Member -MemberType NoteProperty -Name ResourceSPObjectId -Value $assignment.ResourceId
        $objOut | Add-Member -MemberType NoteProperty -Name ResourceSPName -Value $resource.DisplayName
        $objOut | Add-Member -MemberType NoteProperty -Name Scope -Value $appRole.Value

        Select-Object -InputObject $objOut -Property `
        ClientSPObjectId, `
        ClientSPDisplayName, `
        ConsentType, `
        ResourceSPObjectId, `
        ResourceSPName, `
        Scope | Export-Csv -NoTypeInformation -append $outFile
    }
}

Write-Host "`n* Processing completed." -ForegroundColor Green

Write-Host "`nOutput file : $outFile`n" -ForegroundColor Red
