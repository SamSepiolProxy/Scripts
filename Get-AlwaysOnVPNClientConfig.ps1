Get-VpnConnection | out-file -Append -FilePath .\VPNProperties.txt
Get-VpnConnection | Select-Object -ExpandProperty Routes | out-file -Append -FilePath .\VPNProperties.txt
Get-VpnConnection | Select-Object -ExpandProperty IPsecCustomPolicy | out-file -Append -FilePath .\VPNProperties.txt
Get-VpnConnection -AllUserConnection | out-file -Append -FilePath .\VPNProperties.txt
Get-VpnConnection -AllUserConnection | Select-Object -ExpandProperty Routes | out-file -Append -FilePath .\VPNProperties.txt
Get-VpnConnection -AllUserConnection | Select-Object -ExpandProperty IPsecCustomPolicy | out-file -Append -FilePath .\VPNProperties.txt
# // Run under the SYSTEM context for device tunnel or all user connection configuration 
$ConnectionName = "ENTER PROFILE NAME"
$xmlFilePath = ".\vpnprofile.xml"
$ConnectionNameEscaped = $ConnectionName -replace ' ', '%20'
$Xml = Get-CimInstance -Namespace 'root\cimv2\mdm\dmmap' -ClassName 'MDM_VPNv2_01' -Filter "ParentID='./Vendor/MSFT/VPNv2' and InstanceID='$ConnectionNameEscaped'" | Select-Object -ExpandProperty ProfileXML
Function Format-XML ([xml]$Xml, $Indent = 3) { 
    $StringWriter = New-Object System.IO.StringWriter 
    $XmlWriter = New-Object System.XMl.XmlTextWriter $StringWriter 
    $XmlWriter.Formatting = "Indented"
    $XmlWriter.Indentation = $Indent 
    $Xml.WriteContentTo($XmlWriter) 
    $XmlWriter.Flush() 
    $StringWriter.Flush() 
    Write-Output $StringWriter.ToString() 
}
Format-XML $xml | Out-File $xmlFilePath
