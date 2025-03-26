# Define file paths
$EmailListFile = "./emails.txt"  # Path to the file containing email addresses
$LogFile = "./email_log.txt"     # Path to the log file

# Define email details
$Subject = "Subject Header"
$Body = Get-Content "./test.html"  # Modify as necessary
$From = "test@microsoft.co.uk"
$SmtpServer = "test-co-uk.mail.protection.outlook.com"

# Read email addresses from the file
$EmailAddresses = Get-Content -Path $EmailListFile

# Repeat the whole process 50 times
for ($i = 1; $i -le 5; $i++) {
    Write-Host "Iteration $i"
    
    # Loop through each email address and send the email
    foreach ($Email in $EmailAddresses) {
        try {
            # Send the email and force errors to be treated as terminating
            Send-MailMessage -To "$Email" -Subject "$Subject" -Body "$Body" -From "$From" -SmtpServer "$SmtpServer" -BodyAsHtml -Encoding Ascii -ErrorAction Stop
            
            # Log success
            $LogEntry = "{0} - Email sent to {1} (Iteration {2})" -f (Get-Date), $Email, $i
            Add-Content -Path $LogFile -Value $LogEntry
            
            # Print a confirmation message to the console
            Write-Host "Email sent to $Email (Iteration $i)"
        }
        catch {
            # Capture and log the detailed error message
            $ErrorLogEntry = "{0} - Failed to send email to {1} (Iteration {2}): {3}" -f (Get-Date), $Email, $i, $_.Exception.Message
            $DetailedErrorLog = "`nError Details: `n$_"  # Log the full error including line numbers and server response
            Add-Content -Path $LogFile -Value ($ErrorLogEntry + $DetailedErrorLog)
            
            # Print the error message to the console
            Write-Host "Failed to send email to $Email (Iteration $i)"
            Write-Host $_.Exception.Message
        }

        # Wait for 5 seconds before sending the next email
        Start-Sleep -Seconds 5
    }
    
    # Optional: Add a delay between iterations if needed (e.g., 5 seconds)
    Start-Sleep -Seconds 5
}
