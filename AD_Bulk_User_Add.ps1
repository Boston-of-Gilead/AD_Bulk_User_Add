#First portion will ask for user input 

$Ans = Read-Host -prompt “Do you have a science party member to add? Yes/No”

While ($Ans = Yes){

	$FN = Read-Host -Prompt 'Input a first name'
	$LN = Read-Host -Prompt 'Input a last name'
	$AN = Read-Host -Prompt 'Input an account name'
	$CN = Read-Host -Prompt 'Input the cruise’

#adds inputs to CSV:

$Outputstring = $FN,$LN,$AN,$CN
$Outputstring -join “,” >> c:\users\sts-cr\desktop\Users.csv
	$Ans = Read-Host -prompt “Do you have another science party member to add? Yes/No”
	}

#rest of code

#Mass user load for AD on ship

#Add AD bits and not complain if they're already there
Import-Module ActiveDirectory -ErrorAction SilentlyContinue

#Set default password
$defpassword = (ConvertTo-SecureString "sio2016WSAF" -AsPlainText -force)

#Get domain DNS suffix
$dnsroot = '@' + (Get-ADDomain).dnsroot

#Sets target OU as Users\Science
$destinationDN = "OU=Science,CN=Users,DC=<>,DC=<>,DC=<>"

#Import user CSV with user info.
$users = Import-CSV C:\users\sts-cr\desktop\users.csv

$Cruise = Read-Host -Prompt 'Input the Cruise Name (e.g. SR1701)'

(Import-Csv C:\users\sts-cr\desktop\users.csv -Delimiter ',') | ForEach-Object{

 $user.Description = $user.Description -replace "*$", "$Cruise"

    } | Export-Csv C:\users\sts-cr\desktop\users.csv -Delimiter ',' 


foreach ($user in $users) {
            try {
                New-ADUser -SamAccountName ($user.SamAccountName) -Name ($user.Firstname + " " + $user.LastName) -Description ($user.Description) `
                -DisplayName ($user.Firstname + " " + $user.LastName) -GivenName ($user.FirstName) -Surname ($user.LastName) `
                -UserPrincipalName ($user.SamAccountName + $dnsroot) `
                -Enabled $true -ChangePasswordAtLogon $true `
                -AccountPassword $defpassword -PassThru `
                -Path "OU=Science,CN=Users,DC=<>,DC=<>,DC=<>"
                }
            catch [System.Object]
                {
                    Write-Output "Could not create user $($user.SamAccountName), $_ " `
                }
            try {
                Add-ADGroupMember -Identity www-science -Members $user.SamAccountName `
                }
            catch [System.Object]
                {
                    Write-Output "Could not add user to security group $($user.SamAccountName), $_ " 
                }
#            try {  
#               Get-ADUser $user | Move-ADObject -targetpath $destinationDN -whatif  
#                }
#            catch [System.Object]
#                {
#                    Write-Output "Could not add user to OU $($user.SamAccountName), $_ " `
#                }
            }