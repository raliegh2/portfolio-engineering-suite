param([ValidateSet('Application','System','Security','Microsoft-Windows-PowerShell/Operational')][string]$Channel='Application',[ValidateRange(1,500)][int]$Limit=100)
$ErrorActionPreference='Stop'
$portfolioRecords = @(Get-WinEvent -LogName $Channel -MaxEvents $Limit | ForEach-Object {
  $portfolioXml = [xml]$_.ToXml()
  $portfolioData = @{}
  foreach ($portfolioItem in $portfolioXml.Event.EventData.Data) {
    if ($portfolioItem.Name -in @('TargetUserName','SubjectUserName','NewProcessName','CommandLine','ScriptBlockText','TargetSid')) { $portfolioData[$portfolioItem.Name] = $portfolioItem.'#text' }
  }
  @{ recordId=$_.RecordId.ToString(); timeCreated=$_.TimeCreated.ToUniversalTime().ToString('o'); id=$_.Id; machineName=$_.MachineName; provider=$_.ProviderName; eventData=$portfolioData }
})
ConvertTo-Json -InputObject $portfolioRecords -Depth 6 -Compress
