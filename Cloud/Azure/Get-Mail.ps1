param(
    [string]$Token
)

# Set the Graph API endpoints
$ListMessagesUrl = "https://graph.microsoft.com/v1.0/me/messages"

# Define headers for authentication
$Headers = @{
    'Authorization' = "Bearer $token"
    'Content-Type'  = 'application/json'
}

# Fetch list of messages
$MessagesResponse = Invoke-RestMethod -Uri $ListMessagesUrl -Headers $Headers -Method Get

# Check if we received messages
if ($MessagesResponse.value) {
    foreach ($Message in $MessagesResponse.value) {
        $MessageId = $Message.id
        $GetMessageUrl = "https://graph.microsoft.com/v1.0/me/messages/$MessageId"
        
        # Fetch individual message details
        $MessageDetail = Invoke-RestMethod -Uri $GetMessageUrl -Headers $Headers -Method Get
        
        # Extract email body content
        $EmailBody = $MessageDetail.body.content
        
        # Define file name using message ID
        $FileName = "$MessageId.html"
        
        # Save email body to a text file
        $EmailBody | Out-File -FilePath $FileName -Encoding UTF8
        
        Write-Output "Saved email to $FileName"
    }
} else {
    Write-Output "No messages found."
}