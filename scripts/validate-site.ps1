$ErrorActionPreference = 'Stop'

$siteRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$errors = [System.Collections.Generic.List[string]]::new()
$htmlFiles = Get-ChildItem -LiteralPath $siteRoot -Filter '*.html' -File -Recurse |
    Where-Object {
        $_.FullName -notlike "$siteRoot\tmp\*" -and
        $_.FullName -notlike "$siteRoot\github-security-scan\*"
    }

$forbidden = [ordered]@{
    'retired public email' = 'ejor50k@gmail\.com'
    'internal endpoint name' = '\bHAL9000\b'
    'internal IPv4 address' = '\b10\.0\.0\.50\b'
    'provider IPv6 resolver' = '2001:558:feed::1'
    'provider resolver hostname' = 'cdns01\.comcast\.net'
    'provider-specific network copy' = '\b(?:Xfinity|Comcast)\b'
    'superseded operational screenshot' = '(?:pihole-home-network|finalclosetcast-sanitized|wazuh-hal9000-events|ClubAutomation|ethan-playing-piano)'
    'exact routine detail' = '(?:07:30|4:30 PM|Saturday 10|during my commute)'
}

$publicTextFiles = Get-ChildItem -LiteralPath $siteRoot -File -Recurse |
    Where-Object {
        $_.Extension -in '.html', '.css', '.xml', '.txt', '.md' -and
        $_.FullName -notlike "$siteRoot\tmp\*" -and
        $_.FullName -notlike "$siteRoot\github-security-scan\*" -and
        $_.FullName -notlike "$siteRoot\.git\*"
    }

foreach ($file in $publicTextFiles) {
    $content = [System.IO.File]::ReadAllText($file.FullName)
    foreach ($entry in $forbidden.GetEnumerator()) {
        if ($content -match $entry.Value) {
            $relative = [System.IO.Path]::GetRelativePath($siteRoot, $file.FullName)
            $errors.Add("$relative contains $($entry.Key).")
        }
    }
}

foreach ($file in $htmlFiles) {
    $content = [System.IO.File]::ReadAllText($file.FullName)
    $relative = [System.IO.Path]::GetRelativePath($siteRoot, $file.FullName)

    if ($content -notmatch '<!doctype html>') {
        $errors.Add("$relative is missing an HTML doctype.")
    }
    if ($content -notmatch 'Content-Security-Policy') {
        $errors.Add("$relative is missing a Content Security Policy.")
    }
    if ($content -notmatch 'connect-src ''none''') {
        $errors.Add("$relative does not block browser connections.")
    }
    if ($content -notmatch '<meta name="referrer" content="no-referrer">') {
        $errors.Add("$relative is missing the no-referrer policy.")
    }
    if ($relative -ne '404.html' -and $content -notmatch '<link rel="canonical"') {
        $errors.Add("$relative is missing a canonical URL.")
    }

    foreach ($match in [regex]::Matches($content, '(?:href|src)="([^"]+)"')) {
        $target = $match.Groups[1].Value
        if ($target -match '^(?:https?:|mailto:|tel:|data:|#)') {
            continue
        }

        $cleanTarget = ($target -split '[?#]', 2)[0]
        if ([string]::IsNullOrWhiteSpace($cleanTarget)) {
            continue
        }

        if ($cleanTarget.StartsWith('/')) {
            $candidate = Join-Path $siteRoot ($cleanTarget.TrimStart('/').Replace('/', [System.IO.Path]::DirectorySeparatorChar))
        } else {
            $candidate = [System.IO.Path]::GetFullPath((Join-Path $file.DirectoryName $cleanTarget))
        }

        if ($cleanTarget.EndsWith('/')) {
            $candidate = Join-Path $candidate 'index.html'
        }

        if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) {
            $errors.Add("$relative links to missing local target $target.")
        }
    }

    foreach ($anchor in [regex]::Matches($content, '<a\s+[^>]*href="https?://[^"]+"[^>]*>')) {
        if ($anchor.Value -notmatch 'rel="[^"]*noopener[^"]*noreferrer[^"]*"') {
            $errors.Add("$relative has an external link without noopener noreferrer.")
        }
    }
}

if ($errors.Count -gt 0) {
    $errors | Sort-Object -Unique | ForEach-Object { Write-Error $_ }
    throw "Site validation failed with $($errors.Count) finding(s)."
}

Write-Output "Validated $($htmlFiles.Count) HTML pages: policy metadata, privacy guardrails, external-link isolation, and local targets passed."
