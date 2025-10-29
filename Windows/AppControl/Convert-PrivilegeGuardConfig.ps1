<#
.SYNOPSIS
    Converts BeyondTrust Avecto Privilege Guard XML configuration to a single CSV file. This can be found in C:\ProgramData\Avecto\Privilege Guard\GPO Cache\Machine\PrivilegeGuardConfig.xml.

.DESCRIPTION
    This script extracts all configurations from the PrivilegeGuardConfig XML file,
    including mapping Policies to ApplicationGroups with Actions and Account Filters.

.PARAMETER XmlPath
    Path to the PrivilegeGuardConfig XML file.

.PARAMETER OutputFile
    Output CSV file path. Defaults to "PrivilegeGuardConfig.csv" in current directory.

.EXAMPLE
    .\Convert-PrivilegeGuardConfig.ps1 -XmlPath "C:\Config\PrivilegeGuardConfig.xml"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$XmlPath,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputFile = "PrivilegeGuardConfig.csv"
)

# Validate XML file exists
if (-not (Test-Path $XmlPath)) {
    Write-Error "XML file not found: $XmlPath"
    exit 1
}

# Load XML
Write-Host "Loading XML file..." -ForegroundColor Cyan
try {
    [xml]$xml = Get-Content -Path $XmlPath -ErrorAction Stop
} catch {
    Write-Error "Failed to load XML: $_"
    exit 1
}

Write-Host "Building Policy mappings..." -ForegroundColor Cyan

$allRecords = @()

# Build Policy lookup with correct structure navigation
# Structure: Policy > ApplicationAssignments > ApplicationAssignment (contains Action and ApplicationGroup)
# Structure: Policy > Filters > AccountsFilter > Accounts > Account (contains Name, SID, Group)
$policyLookup = @{}
$policies = $xml.SelectNodes("//Policy")

Write-Host "Found $($policies.Count) Policies" -ForegroundColor Gray

foreach ($policy in $policies) {
    $policyID = $policy.GetAttribute('ID')
    
    if ($policyID) {
        Write-Host "`nProcessing Policy ID: $policyID" -ForegroundColor Gray
        
        # Get ALL attributes from policy
        $policyInfo = @{
            PolicyID = $policyID
            PolicyName = $policy.GetAttribute('Name')
            PolicyDescription = $policy.GetAttribute('Description')
            PolicyEnabled = $policy.GetAttribute('Enabled')
        }
        
        foreach ($attr in $policy.Attributes) {
            $policyInfo["Policy_$($attr.Name)"] = $attr.Value
        }
        
        # Navigate to Filters > AccountsFilter > Accounts > Account
        $accountsNode = $policy.SelectSingleNode("./Filters/AccountsFilter/Accounts")
        if (-not $accountsNode) {
            $accountsNode = $policy.SelectSingleNode(".//Filters/AccountsFilter/Accounts")
        }
        if (-not $accountsNode) {
            $accountsNode = $policy.SelectSingleNode(".//AccountsFilter/Accounts")
        }
        if (-not $accountsNode) {
            $accountsNode = $policy.SelectSingleNode(".//Accounts")
        }
        
        if ($accountsNode) {
            # Get all Account child elements
            $accountElements = $accountsNode.SelectNodes("./Account")
            if (-not $accountElements -or $accountElements.Count -eq 0) {
                $accountElements = $accountsNode.SelectNodes(".//Account")
            }
            
            if ($accountElements -and $accountElements.Count -gt 0) {
                $accountsList = @()
                foreach ($account in $accountElements) {
                    # Get Name, SID, and Group from attributes or child elements
                    $name = $account.GetAttribute('Name')
                    if (-not $name) {
                        $nameNode = $account.SelectSingleNode('./Name')
                        if ($nameNode) { $name = $nameNode.InnerText }
                    }
                    
                    $sid = $account.GetAttribute('SID')
                    if (-not $sid) {
                        $sidNode = $account.SelectSingleNode('./SID')
                        if ($sidNode) { $sid = $sidNode.InnerText }
                    }
                    
                    $group = $account.GetAttribute('Group')
                    if (-not $group) {
                        $groupNode = $account.SelectSingleNode('./Group')
                        if ($groupNode) { $group = $groupNode.InnerText }
                    }
                    
                    $accountsList += "$name (SID: $sid, Group: $group)"
                }
                
                $policyInfo['AccountFilter'] = $accountsList -join '; '
                $policyInfo['AccountFilter_Count'] = $accountElements.Count
                Write-Host "  Found $($accountElements.Count) Account(s): $($policyInfo['AccountFilter'])" -ForegroundColor DarkGray
            } else {
                $policyInfo['AccountFilter'] = ""
                $policyInfo['AccountFilter_Count'] = 0
                Write-Host "  No Account elements found under Accounts" -ForegroundColor Yellow
            }
        } else {
            $policyInfo['AccountFilter'] = ""
            $policyInfo['AccountFilter_Count'] = 0
            Write-Host "  No Accounts node found" -ForegroundColor Yellow
        }
        
        # Navigate to ApplicationAssignments > ApplicationAssignment
        $appAssignments = $policy.SelectNodes("./ApplicationAssignments/ApplicationAssignment")
        if (-not $appAssignments -or $appAssignments.Count -eq 0) {
            $appAssignments = $policy.SelectNodes(".//ApplicationAssignments/ApplicationAssignment")
        }
        if (-not $appAssignments -or $appAssignments.Count -eq 0) {
            $appAssignments = $policy.SelectNodes(".//ApplicationAssignment")
        }
        
        if ($appAssignments -and $appAssignments.Count -gt 0) {
            Write-Host "  Found $($appAssignments.Count) ApplicationAssignments" -ForegroundColor DarkGray
            
            # Store each ApplicationAssignment with its Action and ApplicationGroup
            foreach ($appAssignment in $appAssignments) {
                $action = $appAssignment.GetAttribute('Action')
                if (-not $action) {
                    $actionNode = $appAssignment.SelectSingleNode("./Action")
                    if ($actionNode) {
                        $action = $actionNode.InnerText
                    }
                }
                
                $appGroupID = $appAssignment.GetAttribute('ApplicationGroup')
                if (-not $appGroupID) {
                    $appGroupID = $appAssignment.GetAttribute('ApplicationGroupID')
                }
                if (-not $appGroupID) {
                    $appGroupNode = $appAssignment.SelectSingleNode("./ApplicationGroup")
                    if ($appGroupNode) {
                        $appGroupID = $appGroupNode.InnerText
                        if (-not $appGroupID) {
                            $appGroupID = $appGroupNode.GetAttribute('ID')
                        }
                    }
                }
                
                Write-Host "    ApplicationAssignment: AppGroupID=$appGroupID, Action=$action" -ForegroundColor DarkGray
                
                # Create a unique key for this policy + appgroup combination
                if ($appGroupID) {
                    $lookupKey = "$policyID|$appGroupID"
                    
                    $assignmentInfo = $policyInfo.Clone()
                    $assignmentInfo['Action'] = $action
                    $assignmentInfo['Policy_ApplicationGroupID'] = $appGroupID
                    
                    # Add all attributes from ApplicationAssignment
                    foreach ($attr in $appAssignment.Attributes) {
                        $assignmentInfo["ApplicationAssignment_$($attr.Name)"] = $attr.Value
                    }
                    
                    $policyLookup[$lookupKey] = $assignmentInfo
                }
            }
        } else {
            Write-Host "  No ApplicationAssignments found" -ForegroundColor Yellow
        }
    }
}

Write-Host "`nPolicy lookup table contains $($policyLookup.Count) entries" -ForegroundColor Cyan
foreach ($key in $policyLookup.Keys | Select-Object -First 5) {
    Write-Host "  Key '$key' -> Action: $($policyLookup[$key]['Action']), AccountFilter: $($policyLookup[$key]['AccountFilter'])" -ForegroundColor Gray
}

# Function to get all attributes and child elements from an XML element
function Get-AllElementData {
    param(
        [System.Xml.XmlElement]$Element,
        [string]$Prefix = ""
    )
    
    $data = @{}
    
    # Get all attributes
    foreach ($attr in $Element.Attributes) {
        $key = if ($Prefix) { "${Prefix}_$($attr.Name)" } else { $attr.Name }
        $data[$key] = $attr.Value
    }
    
    # Get all child elements
    foreach ($child in $Element.ChildNodes) {
        if ($child.NodeType -eq 'Element') {
            $childName = $child.LocalName
            $key = if ($Prefix) { "${Prefix}_${childName}" } else { $childName }
            
            # If child has only text content
            if ($child.InnerText -and (-not ($child.ChildNodes | Where-Object { $_.NodeType -eq 'Element' }))) {
                $data[$key] = $child.InnerText
            }
            # If child has attributes, add them
            elseif ($child.Attributes.Count -gt 0) {
                foreach ($attr in $child.Attributes) {
                    $data["${key}_$($attr.Name)"] = $attr.Value
                }
                if ($child.InnerText) {
                    $data[$key] = $child.InnerText
                }
            }
        }
    }
    
    return $data
}

# Extract Applications from ApplicationGroups
Write-Host "`nExtracting Applications from ApplicationGroups..." -ForegroundColor Cyan
$applicationGroups = $xml.SelectNodes("//ApplicationGroups/ApplicationGroup")

if ($applicationGroups.Count -gt 0) {
    Write-Host "Found $($applicationGroups.Count) ApplicationGroups" -ForegroundColor Gray
    
    foreach ($appGroup in $applicationGroups) {
        
        $appGroupID = $appGroup.GetAttribute('ID')
        $appGroupName = $appGroup.GetAttribute('Name')
        
        Write-Host "`n  Processing ApplicationGroup '$appGroupName' (ID: $appGroupID)" -ForegroundColor Gray
        
        # Get ApplicationGroup data
        $appGroupData = Get-AllElementData -Element $appGroup -Prefix "ApplicationGroup"
        
        # Find matching policy assignments for this ApplicationGroup
        $matchingPolicies = @()
        foreach ($key in $policyLookup.Keys) {
            if ($key -match "\|$appGroupID$") {
                $matchingPolicies += $policyLookup[$key]
                Write-Host "    MATCHED Policy: $($policyLookup[$key].PolicyName), Action: $($policyLookup[$key]['Action'])" -ForegroundColor Green
            }
        }
        
        if ($matchingPolicies.Count -eq 0) {
            Write-Host "    WARNING: No matching policy found for this ApplicationGroup" -ForegroundColor Yellow
        }
        
        # Get all Applications within this ApplicationGroup
        $applications = $appGroup.SelectNodes("Application")
        
        if ($applications.Count -gt 0) {
            Write-Host "    Found $($applications.Count) Applications" -ForegroundColor DarkGray
            
            foreach ($app in $applications) {
                
                # If multiple policies match, create a record for each
                # If no policies match, create one record with empty policy data
                $policiesToProcess = if ($matchingPolicies.Count -gt 0) { $matchingPolicies } else { @(@{}) }
                
                foreach ($matchingPolicy in $policiesToProcess) {
                    
                    $props = [ordered]@{
                        RecordType = "Application"
                    }
                    
                    # Add matching Policy information
                    if ($matchingPolicy.Count -gt 0) {
                        foreach ($key in $matchingPolicy.Keys) {
                            $props[$key] = $matchingPolicy[$key]
                        }
                    } else {
                        # Add empty policy fields
                        $props['PolicyID'] = ""
                        $props['PolicyName'] = ""
                        $props['Action'] = ""
                        $props['AccountFilter'] = ""
                        $props['AccountFilter_Count'] = 0
                    }
                    
                    # Add ApplicationGroup context
                    foreach ($key in $appGroupData.Keys) {
                        $props[$key] = $appGroupData[$key]
                    }
                    
                    # Add Application attributes
                    foreach ($attr in $app.Attributes) {
                        $props["Application_$($attr.Name)"] = $attr.Value
                    }
                    
                    # Add all child elements of Application
                    foreach ($child in $app.ChildNodes) {
                        if ($child.NodeType -eq 'Element') {
                            $childName = $child.LocalName
                            
                            # Store the element name as-is
                            if ($child.InnerText) {
                                $props[$childName] = $child.InnerText
                            }
                            
                            # Also add any attributes
                            foreach ($attr in $child.Attributes) {
                                $props["${childName}_$($attr.Name)"] = $attr.Value
                            }
                            
                            # If the child has nested elements, flatten them too
                            foreach ($grandChild in $child.ChildNodes) {
                                if ($grandChild.NodeType -eq 'Element') {
                                    $props["${childName}_$($grandChild.LocalName)"] = $grandChild.InnerText
                                }
                            }
                        }
                    }
                    
                    $allRecords += [PSCustomObject]$props
                }
            }
        }
    }
}

# Export to CSV
if ($allRecords -and $allRecords.Count -gt 0) {
    $allRecords | Export-Csv -Path $OutputFile -NoTypeInformation -Encoding UTF8
    Write-Host "`nSuccessfully exported $($allRecords.Count) records to: $OutputFile" -ForegroundColor Green
    
    # Show summary
    Write-Host "`nRecord type summary:" -ForegroundColor Cyan
    $allRecords | Group-Object RecordType | Sort-Object Count -Descending | ForEach-Object {
        Write-Host "  $($_.Name): $($_.Count)" -ForegroundColor Gray
    }
    
    # Verify key columns
    $sampleRecord = $allRecords[0]
    Write-Host "`nVerifying key columns in CSV:" -ForegroundColor Cyan
    Write-Host "  Action: $($sampleRecord.PSObject.Properties.Name -contains 'Action') - Value: '$($sampleRecord.Action)'" -ForegroundColor Gray
    Write-Host "  AccountFilter: $($sampleRecord.PSObject.Properties.Name -contains 'AccountFilter') - Value: '$($sampleRecord.AccountFilter)'" -ForegroundColor Gray
    Write-Host "  PolicyID: $($sampleRecord.PSObject.Properties.Name -contains 'PolicyID') - Value: '$($sampleRecord.PolicyID)'" -ForegroundColor Gray
    
} else {
    Write-Warning "No data found to export"
}

Write-Host "`nConversion completed!" -ForegroundColor Cyan