$LibrariesToLoad = @(
    'Lib\Standard\BouncyCastle.Cryptography.dll'
    'Lib\Standard\PgpCore.dll'
    'Lib\Standard\PSPGP.dll'
)
foreach ($L in $LibrariesToLoad) {
    Add-Type -Path $PSScriptRoot\$L
}