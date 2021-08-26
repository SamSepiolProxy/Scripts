On Error Resume Next
const ADS_UF_DONT_EXPIRE_PASSWD = &H10000
Const ADS_SCOPE_SUBTREE = 2
Set objConnection = CreateObject("ADODB.Connection")
Set objCommand =   CreateObject("ADODB.Command")
objConnection.Provider = "ADsDSOObject"
objConnection.Open "Active Directory Provider"
Set objCommand.ActiveConnection = objConnection
objCommand.Properties("Page Size") = 1500
objCommand.Properties("Searchscope") = ADS_SCOPE_SUBTREE
objCommand.CommandText = _
    "SELECT * FROM 'LDAP://dc=DOMAIN,dc=NET' WHERE objectCategory='user'" 
Set objRecordSet = objCommand.Execute
objRecordSet.MoveFirst
Wscript.StdOut.Write """SamAccountName"",""Full Name"",""Created"",""Last Login"",""PasswordChanged"",""Password Never Expires""" & vbCrlf
Do Until objRecordSet.EOF
    strPath = objRecordSet.Fields("ADsPath").Value
    Set objUser = GetObject(strPath)
 
 IF IsEmpty(objUser.samAccountName) THEN
  'Do Nothing
 ELSE
  Wscript.StdOut.Write """" & objUser.samAccountName & ""","
  IF IsEmpty(objUser.FullName) THEN
   Wscript.StdOut.Write """NONE"","
  ELSE
   Wscript.StdOut.Write """" & objUser.FullName & ""","
  END IF
  IF IsEmpty(objUser.whenCreated) THEN
   Wscript.StdOut.Write """NONE"","
  ELSE
   Wscript.StdOut.Write """" & objUser.whenCreated & ""","
  END IF
  IF IsEmpty(objUser.GET("lastLogon")) THEN
   Wscript.StdOut.Write """1/1/1601"","
  Else
   dim intLogonTime
   Set objLogon = objUser.Get("lastLogon")
   intLogonTime = objLogon.HighPart * (2^32) + objLogon.LowPart
   intLogonTime = intLogonTime / (60 * 10000000)
   intLogonTime = intLogonTime / 1440
   intLogonTime = intLogonTime + #1/1/1601#
   inactiveDays = intLogonTime
   Wscript.StdOut.Write """" & inactiveDays & ""","
  END IF
  IF IsEmpty(objUser.passwordLastChanged) THEN
   Wscript.StdOut.Write """1/1/1900 12:00:00 AM"","
  Else
   Wscript.StdOut.Write """" & objUser.passwordLastChanged & ""","
  END IF
  IF objUser.GET("userAccountControl") AND ADS_UF_DONT_EXPIRE_PASSWD THEN
   Wscript.StdOut.Write """" & "TRUE" & """"
  ELSE
   Wscript.StdOut.Write """" & "FALSE" & """"
  END IF
  Wscript.StdOut.WriteLine
 End If
    objRecordSet.MoveNext
Loop