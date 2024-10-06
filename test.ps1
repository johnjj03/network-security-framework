suricata -l logs -k none -r static\uploads\2021-09-20-squirrelwaffle.pcap; 
echo "Suricata event types:"
Get-Content logs/eve.json | jq -r .event_type | Sort-Object | Group-Object | Sort-Object Count -Descending | ForEach-Object { "$($_.Count) $($_.Name)" }

echo "Alerts:"
Select-String -Path logs/eve.json -Pattern '"event_type":"alert"' | ForEach-Object { $_.Line } | jq .alert.signature | Sort-Object | Group-Object | Sort-Object Count -Descending | ForEach-Object { "$($_.Count) $($_.Name)" }

echo "TLS SNIs:"
Get-Content logs\eve.json | ConvertFrom-Json | 
Where-Object { $_.event_type -eq 'tls' -and $_.tls.sni } | 
Select-Object -ExpandProperty tls | 
Select-Object -ExpandProperty sni | 
Group-Object | 
Sort-Object Count -Descending | 
Select-Object @{N='Count';E={$_.Count}}, @{N='SNI';E={$_.Name}}
Format-Table -AutoSize

echo "TLS Versions:"
Get-Content logs/eve.json | ConvertFrom-Json | 
Where-Object { $_.event_type -eq 'tls' -and $_.tls.version } | 
Select-Object -ExpandProperty tls | 
Select-Object -ExpandProperty version | 
Group-Object | 
Sort-Object Count -Descending | 
Select-Object @{N='Count';E={$_.Count}}, @{N='Version';E={$_.Name}} | 
Format-Table -AutoSize

echo "HTTP Hostnames:"
Get-Content logs/eve.json | ConvertFrom-Json | 
Where-Object { $_.event_type -eq 'http' -and $_.http.hostname } | 
Select-Object -ExpandProperty http | 
Select-Object -ExpandProperty hostname | 
Group-Object | 
Sort-Object Count -Descending | 
Select-Object @{N='Count';E={$_.Count}}, @{N='Hostname';E={$_.Name}} | 
Format-Table -AutoSize

echo "DNS Queries:"
Get-Content logs/eve.json | ConvertFrom-Json | 
Where-Object { $_.event_type -eq 'dns' -and $_.dns.rrname } | 
Select-Object -ExpandProperty dns | 
Select-Object -ExpandProperty rrname | 
Group-Object | 
Sort-Object Count -Descending | 
Select-Object @{N='Count';E={$_.Count}}, @{N='Query';E={$_.Name}} | 
Format-Table -AutoSize

echo "Filenames:"
Get-Content logs/eve.json | ConvertFrom-Json | 
Where-Object { $_.event_type -eq 'fileinfo' -and $_.fileinfo.filename } | 
Select-Object -ExpandProperty fileinfo | 
Select-Object -ExpandProperty filename | 
Group-Object | 
Sort-Object Count -Descending | 
Select-Object @{N='Count';E={$_.Count}}, @{N='Filename';E={$_.Name}} | 
Format-Table -AutoSize

echo "File magic:"
Get-Content logs/eve.json | ConvertFrom-Json | 
Where-Object { $_.event_type -eq 'fileinfo' -and $_.fileinfo.magic } | 
Select-Object -ExpandProperty fileinfo | 
Select-Object -ExpandProperty magic | 
Group-Object | 
Sort-Object Count -Descending | 
Select-Object @{N='Count';E={$_.Count}}, @{N='Magic';E={$_.Name}} | 
Format-Table -AutoSize