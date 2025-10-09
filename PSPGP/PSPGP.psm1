# Get library name, from the PSM1 file name
$LibraryName = 'PSPGP'
$Library = "$LibraryName.dll"
$Class = "$LibraryName.Initialize"

$AssemblyFolders = Get-ChildItem -Path $PSScriptRoot\Lib -Directory -ErrorAction SilentlyContinue

# Lets find which libraries we need to load
$Default = $false
$Core = $false
$Standard = $false
foreach ($A in $AssemblyFolders.Name) {
    if ($A -eq 'Default') {
        $Default = $true
    } elseif ($A -eq 'Core') {
        $Core = $true
    } elseif ($A -eq 'Standard') {
        $Standard = $true
    }
}
if ($Standard -and $Core -and $Default) {
    $FrameworkNet = 'Default'
    $Framework = 'Standard'
} elseif ($Standard -and $Core) {
    $Framework = 'Standard'
    $FrameworkNet = 'Standard'
} elseif ($Core -and $Default) {
    $Framework = 'Core'
    $FrameworkNet = 'Default'
} elseif ($Standard -and $Default) {
    $Framework = 'Standard'
    $FrameworkNet = 'Default'
} elseif ($Standard) {
    $Framework = 'Standard'
    $FrameworkNet = 'Standard'
} elseif ($Core) {
    $Framework = 'Core'
    $FrameworkNet = ''
} elseif ($Default) {
    $Framework = ''
    $FrameworkNet = 'Default'
} else {
    Write-Error -Message 'No assemblies found'
}
if ($PSEdition -eq 'Core') {
    $LibFolder = $Framework
} else {
    $LibFolder = $FrameworkNet
}

try {
    $ImportModule = Get-Command -Name Import-Module -Module Microsoft.PowerShell.Core

    if (-not ($Class -as [type])) {
        & $ImportModule ([IO.Path]::Combine($PSScriptRoot, 'Lib', $LibFolder, $Library)) -ErrorAction Stop
    } else {
        $Type = "$Class" -as [Type]
        & $importModule -Force -Assembly ($Type.Assembly)
    }
} catch {
    if ($ErrorActionPreference -eq 'Stop') {
        throw
    } else {
        Write-Warning -Message "Importing module $Library failed. Fix errors before continuing. Error: $($_.Exception.Message)"
        # we will continue, but it's not a good idea to do so
        # return
    }
}
# Dot source all libraries by loading external file
. $PSScriptRoot\PSPGP.Libraries.ps1

function New-PGPKey {
    [cmdletBinding(DefaultParameterSetName = 'ClearText')]
    param(
        [parameter(Mandatory, ParameterSetName = 'Strength')]
        [parameter(Mandatory, ParameterSetName = 'StrengthCredential')]
        [parameter(Mandatory, ParameterSetName = 'ClearText')]
        [parameter(Mandatory, ParameterSetName = 'Credential')]
        [string] $FilePathPublic,
        [parameter(Mandatory, ParameterSetName = 'Strength')]
        [parameter(Mandatory, ParameterSetName = 'StrengthCredential')]
        [parameter(Mandatory, ParameterSetName = 'ClearText')]
        [parameter(Mandatory, ParameterSetName = 'Credential')]
        [string] $FilePathPrivate,
        [parameter(ParameterSetName = 'Strength')]
        [parameter(ParameterSetName = 'ClearText')]
        [string] $UserName,
        [parameter(ParameterSetName = 'Strength')]
        [parameter(ParameterSetName = 'ClearText')]
        [string] $Password,
        [parameter(Mandatory, ParameterSetName = 'StrengthCredential')]
        [parameter(Mandatory, ParameterSetName = 'Credential')]
        [pscredential] $Credential,
        [parameter(Mandatory, ParameterSetName = 'Strength')]
        [parameter(Mandatory, ParameterSetName = 'StrengthCredential')]
        [int] $Strength,
        [parameter(Mandatory, ParameterSetName = 'Strength')]
        [parameter(Mandatory, ParameterSetName = 'StrengthCredential')]
        [int] $Certainty,
        [parameter(ParameterSetName = 'Strength')]
        [parameter(ParameterSetName = 'StrengthCredential')]
        [switch] $EmitVersion,

        [alias('HashAlgorithmTag')][Org.BouncyCastle.Bcpg.HashAlgorithmTag] $HashAlgorithm,
        [Org.BouncyCastle.Bcpg.CompressionAlgorithmTag] $CompressionAlgorithm,
        [PgpCore.Enums.PGPFileType] $FileType,
        [Int32] $PgpSignatureType,
        [Org.BouncyCastle.Bcpg.PublicKeyAlgorithmTag] $PublicKeyAlgorithm,
        [Org.BouncyCastle.Bcpg.SymmetricKeyAlgorithmTag] $SymmetricKeyAlgorithm
    )
    try {
        $PGP = [PgpCore.PGP]::new()
    } catch {
        if ($PSBoundParameters.ErrorAction -eq 'Stop') {
            throw
        } else {
            Write-Warning -Message "New-PGPKey - Creating keys genarated erorr: $($_.Exception.Message)"
            return
        }
    }
    if ($Credential) {
        $UserName = $Credential.UserName
        $Password = $Credential.GetNetworkCredential().Password
    }

    if ($PSBoundParameters.ContainsKey('HashAlgorithm')) {
        $PGP.HashAlgorithmTag = $HashAlgorithm
    }
    if ($PSBoundParameters.ContainsKey('CompressionAlgorithm')) {
        $PGP.CompressionAlgorithm = $CompressionAlgorithm
    }
    if ($PSBoundParameters.ContainsKey('FileType')) {
        $PGP.FileType = $FileType
    }
    if ($PSBoundParameters.ContainsKey('PgpSignatureType')) {
        $PGP.PgpSignatureType = $PgpSignatureType
    }
    if ($PSBoundParameters.ContainsKey('PublicKeyAlgorithm')) {
        $PGP.PublicKeyAlgorithm = $PublicKeyAlgorithm
    }
    if ($PSBoundParameters.ContainsKey('SymmetricKeyAlgorithm')) {
        $PGP.SymmetricKeyAlgorithm = $SymmetricKeyAlgorithm
    }

    $ResolvedPublicKey = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($FilePathPublic)
    $ResolvedPrivateKey = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($FilePathPrivate)

    try {
        if ($Strength) {
            $PGP.GenerateKey($ResolvedPublicKey, $ResolvedPrivateKey, $UserName, $Password, $Strength, $Certainty, $EmitVersion.IsPresent)
        } else {
            $PGP.GenerateKey($ResolvedPublicKey, $ResolvedPrivateKey, $UserName, $Password)
        }
    } catch {
        if ($PSBoundParameters.ErrorAction -eq 'Stop') {
            throw
        } else {
            Write-Warning -Message "New-PGPKey - Creating keys genarated error: $($_.Exception.Message)"
            return
        }
    }

    #void GenerateKey(string publicKeyFilePath, string privateKeyFilePath, string username, string password, int strength, int certainty, bool emitVersion)
    #void GenerateKey(System.IO.Stream publicKeyStream, System.IO.Stream privateKeyStream, string username, string password, int strength, int certainty, bool armor, bool emitVersion)
}

function Protect-PGP {
    [cmdletBinding(DefaultParameterSetName = 'File')]
    param(
        [Parameter(Mandatory, ParameterSetName = 'Folder')]
        [Parameter(Mandatory, ParameterSetName = 'File')]
        [Parameter(Mandatory, ParameterSetName = 'String')]
        [string[]] $FilePathPublic,

        [Parameter(Mandatory, ParameterSetName = 'Folder')][string] $FolderPath,
        [Parameter(ParameterSetName = 'Folder')][string] $OutputFolderPath,

        [Parameter(Mandatory, ParameterSetName = 'File')][string] $FilePath,
        [Parameter(ParameterSetName = 'File')][string] $OutFilePath,

        [Parameter(Mandatory, ParameterSetName = 'String')][string] $String,

        [System.IO.FileInfo] $SignKey,
        [string] $SignPassword,
        [alias('HashAlgorithmTag')][Org.BouncyCastle.Bcpg.HashAlgorithmTag] $HashAlgorithm,
        [Org.BouncyCastle.Bcpg.CompressionAlgorithmTag] $CompressionAlgorithm,
        [PgpCore.Enums.PGPFileType] $FileType,
        [Int32] $PgpSignatureType,
        [Org.BouncyCastle.Bcpg.PublicKeyAlgorithmTag] $PublicKeyAlgorithm,
        [Org.BouncyCastle.Bcpg.SymmetricKeyAlgorithmTag] $SymmetricKeyAlgorithm

    )
    $PublicKeys = [System.Collections.Generic.List[System.IO.FileInfo]]::new()
    foreach ($FilePathPubc in $FilePathPublic) {
        $ResolvedPublicKey = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($FilePathPubc)
        if (Test-Path -LiteralPath $ResolvedPublicKey) {
            $PublicKeys.Add([System.IO.FileInfo]::new($ResolvedPublicKey))
        } else {
            if ($PSBoundParameters.ErrorAction -eq 'Stop') {
                throw
            } else {
                Write-Warning -Message "Protect-PGP - Public key doesn't exists $($ResolvedPublicKey): $($_.Exception.Message)"
                return
            }
        }
    }
    try {
        if ($SignKey) {
            $EncryptionKeys = [PgpCore.EncryptionKeys]::new($PublicKeys, $SignKey, $SignPassword)
        } else {
            $EncryptionKeys = [PgpCore.EncryptionKeys]::new($PublicKeys)
        }
        $PGP = [PgpCore.PGP]::new($EncryptionKeys)
    } catch {
        if ($PSBoundParameters.ErrorAction -eq 'Stop') {
            throw
        } else {
            Write-Warning -Message "Protect-PGP - Can't encrypt files because: $($_.Exception.Message)"
            return
        }
    }

    if ($PSBoundParameters.ContainsKey('HashAlgorithm')) {
        $PGP.HashAlgorithmTag = $HashAlgorithm
    }
    if ($PSBoundParameters.ContainsKey('CompressionAlgorithm')) {
        $PGP.CompressionAlgorithm = $CompressionAlgorithm
    }
    if ($PSBoundParameters.ContainsKey('FileType')) {
        $PGP.FileType = $FileType
    }
    if ($PSBoundParameters.ContainsKey('PgpSignatureType')) {
        $PGP.PgpSignatureType = $PgpSignatureType
    }
    if ($PSBoundParameters.ContainsKey('PublicKeyAlgorithm')) {
        $PGP.PublicKeyAlgorithm = $PublicKeyAlgorithm
    }
    if ($PSBoundParameters.ContainsKey('SymmetricKeyAlgorithm')) {
        $PGP.SymmetricKeyAlgorithm = $SymmetricKeyAlgorithm
    }

    if ($FolderPath) {
        $ResolvedFolderPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($FolderPath)
        foreach ($File in Get-ChildItem -LiteralPath $ResolvedFolderPath -Recurse:$Recursive) {
            try {
                if ($OutputFolderPath) {
                    $ResolvedOutputFolder = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputFolderPath)
                    $OutputFile = [io.Path]::Combine($ResolvedOutputFolder, "$($File.Name).pgp")
                    if ($SignKey) {
                        $PGP.EncryptFileAndSign($File.FullName, $Outputfile)
                    } else {
                        $PGP.EncryptFile($File.FullName, $OutputFile)
                    }
                } else {
                    if ($SignKey) {
                        $PGP.EncryptFileAndSign($File.FullName, "$($File.FullName).pgp")
                    } else {
                        $PGP.EncryptFile($File.FullName, "$($File.FullName).pgp")
                    }
                }
            } catch {
                if ($PSBoundParameters.ErrorAction -eq 'Stop') {
                    throw
                } else {
                    Write-Warning -Message "Protect-PGP - Can't encrypt file $($File.FullName): $($_.Exception.Message)"
                    return
                }
            }
        }
    } elseif ($FilePath) {
        try {
            $ResolvedFilePath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($FilePath)
            if ($OutFilePath) {
                $ResolvedOutFilePath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutFilePath)
                if ($SignKey) {
                    $PGP.EncryptFileAndSign($ResolvedFilePath, $ResolvedOutFilePath)
                } else {
                    $PGP.EncryptFile($ResolvedFilePath, $ResolvedOutFilePath)
                }
            } else {
                if ($SignKey) {
                    $PGP.EncryptFileAndSign($ResolvedFilePath, "$($ResolvedFilePath).pgp")
                } else {
                    $PGP.EncryptFile($ResolvedFilePath, "$($ResolvedFilePath).pgp")
                }
            }
        } catch {
            if ($PSBoundParameters.ErrorAction -eq 'Stop') {
                throw
            } else {
                Write-Warning -Message "Protect-PGP - Can't encrypt file $($FilePath): $($_.Exception.Message)"
                return
            }
        }
    } elseif ($String) {
        try {
            if ($SignKey) {
                $PGP.EncryptArmoredStringAndSign($String)
            } else {
                $PGP.EncryptArmoredString($String)
            }
        } catch {
            if ($PSBoundParameters.ErrorAction -eq 'Stop') {
                throw
            } else {
                Write-Warning -Message "Protect-PGP - Can't encrypt string: $($_.Exception.Message)"
            }
        }
    }
}

function Test-PGP {
    [cmdletBinding(DefaultParameterSetName = 'File')]
    param(
        [Parameter(Mandatory, ParameterSetName = 'Folder')]
        [Parameter(Mandatory, ParameterSetName = 'File')]
        [Parameter(Mandatory, ParameterSetName = 'String')]
        [string] $FilePathPublic,

        [Parameter(Mandatory, ParameterSetName = 'Folder')][string] $FolderPath,
        [Parameter(ParameterSetName = 'Folder')][string] $OutputFolderPath,

        [Parameter(Mandatory, ParameterSetName = 'File')][string] $FilePath,
        [Parameter(ParameterSetName = 'File')][string] $OutFilePath,

        [Parameter(Mandatory, ParameterSetName = 'String')][string] $String
    )

    $ResolvedPublicKey = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($FilePathPublic)
    if (Test-Path -LiteralPath $ResolvedPublicKey) {
        $PublicKey = [System.IO.FileInfo]::new($ResolvedPublicKey)
    } else {
        if ($PSBoundParameters.ErrorAction -eq 'Stop') {
            throw
        } else {
            Write-Warning -Message "Test-PGP - Public key doesn't exists $($ResolvedPublicKey): $($_.Exception.Message)"
            return
        }
    }
    try {
        $EncryptionKeys = [PgpCore.EncryptionKeys]::new($PublicKey)
        $PGP = [PgpCore.PGP]::new($EncryptionKeys)
    } catch {
        if ($PSBoundParameters.ErrorAction -eq 'Stop') {
            throw
        } else {
            Write-Warning -Message "Test-PGP - Can't test files because: $($_.Exception.Message)"
            return
        }
    }
    if ($FolderPath) {
        $ResolvedFolderPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($FolderPath)
        foreach ($File in Get-ChildItem -LiteralPath $ResolvedFolderPath -Recurse:$Recursive) {
            try {
                $Output = $PGP.VerifyFile($File.FullName)
                $ErrorMessage = ''
            } catch {
                $Output = $false
                if ($PSBoundParameters.ErrorAction -eq 'Stop') {
                    throw
                } else {
                    Write-Warning -Message "Test-PGP - Can't test file $($File.FuleName): $($_.Exception.Message)"
                    $ErrorMessage = $($_.Exception.Message)
                }
            }
            [PSCustomObject] @{
                FilePath = $File.FullName
                Status   = $Output
                Error    = $ErrorMessage
            }
        }
    } elseif ($FilePath) {
        $ResolvedFilePath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($FilePath)
        try {
            $Output = $PGP.VerifyFile($ResolvedFilePath)
        } catch {
            $Output = $false
            if ($PSBoundParameters.ErrorAction -eq 'Stop') {
                throw
            } else {
                Write-Warning -Message "Test-PGP - Can't test file $($ResolvedFilePath): $($_.Exception.Message)"
                $ErrorMessage = $($_.Exception.Message)
            }
        }
        [PSCustomObject] @{
            FilePath = $ResolvedFilePath
            Status   = $Output
            Error    = $ErrorMessage
        }
    } elseif ($String) {
        try {
            $PGP.VerifyArmoredString($String)
        } catch {
            if ($PSBoundParameters.ErrorAction -eq 'Stop') {
                throw
            } else {
                Write-Warning -Message "Test-PGP - Can't test string: $($_.Exception.Message)"
            }
        }
    }
}
function Unprotect-PGP {
    [cmdletBinding(DefaultParameterSetName = 'FolderClearText')]
    param(
        [Parameter(Mandatory, ParameterSetName = 'FolderCredential')]
        [Parameter(Mandatory, ParameterSetName = 'FolderClearText')]
        [Parameter(Mandatory, ParameterSetName = 'FileCredential')]
        [Parameter(Mandatory, ParameterSetName = 'FileClearText')]
        [Parameter(Mandatory, ParameterSetName = 'StringClearText')]
        [Parameter(Mandatory, ParameterSetName = 'StringCredential')]
        [string] $FilePathPrivate,

        [Parameter(ParameterSetName = 'FolderClearText')]
        [Parameter(ParameterSetName = 'FileClearText')]
        [Parameter(ParameterSetName = 'StringClearText')]
        [string] $Password,

        [Parameter(Mandatory, ParameterSetName = 'FileCredential')]
        [Parameter(Mandatory, ParameterSetName = 'FolderCredential')]
        [Parameter(Mandatory, ParameterSetName = 'StringCredential')]
        [pscredential] $Credential,

        [Parameter(Mandatory, ParameterSetName = 'FolderCredential')]
        [Parameter(Mandatory, ParameterSetName = 'FolderClearText')]
        [string] $FolderPath,

        [Parameter(Mandatory, ParameterSetName = 'FolderCredential')]
        [Parameter(Mandatory, ParameterSetName = 'FolderClearText')]
        [string] $OutputFolderPath,

        [Parameter(Mandatory, ParameterSetName = 'FileCredential')]
        [Parameter(Mandatory, ParameterSetName = 'FileClearText')]
        [string] $FilePath,

        [Parameter(Mandatory, ParameterSetName = 'FileCredential')]
        [Parameter(Mandatory, ParameterSetName = 'FileClearText')]
        [string] $OutFilePath,

        [Parameter(Mandatory, ParameterSetName = 'StringClearText')]
        [Parameter(Mandatory, ParameterSetName = 'StringCredential')]
        [string] $String
    )



    if ($Credential) {
        $Password = $Credential.GetNetworkCredential().Password
    }

    $ResolvedPrivateFile = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($FilePathPrivate)
    if (-not (Test-Path -LiteralPath $ResolvedPrivateFile)) {
        Write-Warning -Message "Unprotect-PGP - Remove PGP encryption failed because private key file doesn't exists."
        return
    }
    $PrivateKey = Get-Content -LiteralPath $ResolvedPrivateFile -Raw
    try {
        $EncryptionKeys = [PgpCore.EncryptionKeys]::new($PrivateKey, $Password)

        $PGP = [PgpCore.PGP]::new($EncryptionKeys)
    } catch {
        if ($PSBoundParameters.ErrorAction -eq 'Stop') {
            throw
        } else {
            Write-Warning -Message "Unprotect-PGP - Can't decrypt files because: $($_.Exception.Message)"
            return
        }
    }
    if ($FolderPath) {
        $ResolvedFolderPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($FolderPath)
        foreach ($File in Get-ChildItem -LiteralPath $ResolvedFolderPath -Recurse:$Recursive) {
            try {
                if ($OutputFolderPath) {
                    $ResolvedOutputFolder = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputFolderPath)
                    $OutputFile = [io.Path]::Combine($ResolvedOutputFolder, "$($File.Name.Replace('.pgp',''))")
                    $PGP.DecryptFile($File.FullName, $OutputFile)
                } else {
                    $PGP.DecryptFile($File.FullName, "$($File.FullName)")
                }
            } catch {
                if ($PSBoundParameters.ErrorAction -eq 'Stop') {
                    throw
                } else {
                    Write-Warning -Message "Unprotect-PGP - Remove PGP encryption from $($File.FullName) failed: $($_.Exception.Message)"
                    return
                }
            }
        }
    } elseif ($FilePath) {
        try {
            $ResolvedFilePath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($FilePath)
            if ($OutFilePath) {
                $ResolvedOutFilePath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutFilePath)
                $PGP.DecryptFile($ResolvedFilePath, $ResolvedOutFilePath)
            } else {
                $PGP.DecryptFile($ResolvedFilePath, "$($FilePath.Replace('.pgp',''))")
            }
        } catch {
            if ($PSBoundParameters.ErrorAction -eq 'Stop') {
                throw
            } else {
                Write-Warning -Message "Unprotect-PGP - Remove PGP encryption from $($FilePath) failed: $($_.Exception.Message)"
                return
            }
        }
    } elseif ($String) {
        try {
            $PGP.DecryptArmoredString($String)
        } catch {
            if ($PSBoundParameters.ErrorAction -eq 'Stop') {
                throw
            } else {
                Write-Warning -Message "Unprotect-PGP - Remove PGP encryption from string failed: $($_.Exception.Message)"
                return
            }
        }
    }
}



if ($PSVersionTable.PSEdition -eq 'Desktop' -and (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full").Release -lt 461808) {
    Write-Warning "This module requires .NET Framework 4.7.2 or later."; return 
} 

# Export functions and aliases as required
Export-ModuleMember -Function @('New-PGPKey', 'Protect-PGP', 'Test-PGP', 'Unprotect-PGP') -Alias @()