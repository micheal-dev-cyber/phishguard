param(
    [Parameter(Mandatory = $true)]
    [string]$WebhookUrl
)

$token = "CQhSANYK0bHtZIJwpIocWlSx7zWE807NU6dlWp4y_MU"
$resources = @("sale", "refund", "cancellation", "subscription_updated", "subscription_ended", "subscription_restarted")

$postUrl = $WebhookUrl.TrimEnd('/') + "/webhooks/gumroad"
Write-Output "Registering resource subscriptions → $postUrl"
Write-Output ""

$allOk = $true
foreach ($r in $resources) {
    try {
        $body = @{
            access_token  = $token
            resource_name = $r
            post_url      = $postUrl
        }
        $result = Invoke-RestMethod -Uri "https://api.gumroad.com/v2/resource_subscriptions" -Body $body -Method Post
        if ($result.success) {
            Write-Output "  ✅ $r — registered"
        } else {
            Write-Output "  ❌ $r — $($result.message)"
            $allOk = $false
        }
    } catch {
        Write-Output "  ❌ $r — $($_.Exception.Message)"
        $allOk = $false
    }
}

Write-Output ""
if ($allOk) {
    Write-Output "All 6 resource subscriptions registered successfully!"
} else {
    Write-Output "Some registrations failed — check errors above."
}
