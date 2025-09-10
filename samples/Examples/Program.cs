using LibOQS.NET;
using Spectre.Console;
using System.Text;

namespace Examples;

class Program
{
    static void Main(string[] args)
    {
        AnsiConsole.Write(
            new FigletText("LibOQS.NET")
                .LeftJustified()
                .Color(Color.Blue));

        AnsiConsole.Write(
            new Panel("A .NET wrapper for liboqs - Post-Quantum Cryptography")
                .BorderColor(Color.Blue)
                .Header("[yellow]Welcome[/]"));

        var demo = AnsiConsole.Prompt(
            new SelectionPrompt<string>()
                .Title("Choose the [green]demo[/] to run?")
                .AddChoices([
                    "ML-KEM (Key Encapsulation)",
                        "ML-DSA (Digital Signature)",
                        "Signed Key Exchange",
                        "Algorithm Comparison",
                        "Exit"
                ]));

        switch (demo)
        {
            case "ML-KEM (Key Encapsulation)":
                LibOqsDemo.RunMlKem();
                break;
            case "ML-DSA (Digital Signature)":
                LibOqsDemo.RunMlDsa();
                break;
            case "Signed Key Exchange":
                LibOqsDemo.RunSignedKeyExchange();
                break;
            case "Algorithm Comparison":
                LibOqsDemo.RunAlgorithmComparison();
                break;
            case "Exit":
                return;
        }

        LibOqs.Cleanup();
    }
}

public static class LibOqsDemo
{
    public static void RunMlDsa()
    {
        AnsiConsole.Write(new Rule("[blue]ML-DSA Digital Signature Demo[/]").RuleStyle("blue"));

        var raw = "Hello, ML-DSA from LibOQS.NET!";
        var data = Encoding.UTF8.GetBytes(raw);
        
        PrintPanel("Message", [
            $"Raw: {raw}",
            $"Encoded: {data.PrettyPrint()}"
        ]);

        if (!SigAlgorithm.MlDsa65.IsEnabled())
        {
            PrintPanel("Error", ["ML-DSA-65 is not enabled in this build"]);
            return;
        }

        using var sig = new SigInstance(SigAlgorithm.MlDsa65);

        // Generate key pair
        var (publicKey, secretKey) = sig.GenerateKeypair();
        PrintPanel("Alice's Keys", [
            $":unlocked: Public ({publicKey.Length} bytes): {publicKey.PrettyPrint()}",
            $":locked: Secret ({secretKey.Length} bytes): {secretKey.PrettyPrint()}"
        ]);

        // Sign
        var signature = sig.Sign(data, secretKey);
        PrintPanel("Signature", [
            $":pen: Signature ({signature.Length} bytes): {signature.PrettyPrint()}"
        ]);

        // Verify signature
        var verified = sig.Verify(data, signature, publicKey);
        PrintPanel("Verification", [
            $"{(verified ? ":check_mark_button:" : ":cross_mark:")} Signature verified: {verified}"
        ]);

        // Test with tampered message
        var tamperedData = Encoding.UTF8.GetBytes("Hello, ML-DSA from LibOQS.NET? (tampered)");
        var tamperedVerified = sig.Verify(tamperedData, signature, publicKey);
        PrintPanel("Tamper Test", [
            $"Tampered message: {Encoding.UTF8.GetString(tamperedData)}",
            $"{(tamperedVerified ? ":cross_mark:" : ":check_mark_button:")} Tampered verification: {tamperedVerified} (should be false)"
        ]);
    }

    public static void RunMlKem()
    {
        AnsiConsole.Write(new Rule("[green]ML-KEM Key Encapsulation Demo[/]").RuleStyle("green"));

        if (!KemAlgorithm.MlKem768.IsEnabled())
        {
            PrintPanel("Error", ["ML-KEM-768 is not enabled in this build"]);
            return;
        }

        using var kem = new KemInstance(KemAlgorithm.MlKem768);

        // Generate Alice's key pair
        var (alicePublicKey, aliceSecretKey) = kem.GenerateKeypair();
        PrintPanel("Alice's Keys", [
            $":unlocked: Public ({alicePublicKey.Length} bytes): {alicePublicKey.PrettyPrint()}",
            $":locked: Secret ({aliceSecretKey.Length} bytes): {aliceSecretKey.PrettyPrint()}"
        ]);

        // Bob encapsulates a shared secret using Alice's public key
        var (ciphertext, bobSharedSecret) = kem.Encapsulate(alicePublicKey);

        // Alice decapsulates the shared secret using her secret key
        var aliceSharedSecret = kem.Decapsulate(aliceSecretKey, ciphertext);

        PrintPanel("Key Encapsulation", [
            $":man: Bob's shared secret ({bobSharedSecret.Length} bytes): {bobSharedSecret.PrettyPrint()}",
            $":locked_with_key: Ciphertext Bob → Alice ({ciphertext.Length} bytes): {ciphertext.PrettyPrint()}",
            $":woman: Alice's shared secret ({aliceSharedSecret.Length} bytes): {aliceSharedSecret.PrettyPrint()}"
        ]);

        // Compare secrets
        var equal = bobSharedSecret.SequenceEqual(aliceSharedSecret);
        PrintPanel("Verification", [
            $"{(equal ? ":check_mark_button:" : ":cross_mark:")} Shared secrets match: {equal}"
        ]);
    }

    public static void RunSignedKeyExchange()
    {
        AnsiConsole.Write(new Rule("[purple]Signed Key Exchange Demo[/]").RuleStyle("purple"));

        if (!SigAlgorithm.MlDsa44.IsEnabled() || !KemAlgorithm.MlKem512.IsEnabled())
        {
            PrintPanel("Error", ["Required algorithms (ML-DSA-44, ML-KEM-512) are not enabled in this build"]);
            return;
        }

        using var sigAlg = new SigInstance(SigAlgorithm.MlDsa44);
        using var kemAlg = new KemInstance(KemAlgorithm.MlKem512);

        PrintPanel("Step 1: Setup", ["Generating long-term signature keys for Alice and Bob"]);

        // A's long-term secrets
        var (aSigPk, aSigSk) = sigAlg.GenerateKeypair();
        PrintPanel("Alice's Long-term Keys", [
            $":woman: Alice Signature Public: {aSigPk.PrettyPrint()}",
            $":locked: Alice Signature Secret: {aSigSk.PrettyPrint()}"
        ]);

        // B's long-term secrets
        var (bSigPk, bSigSk) = sigAlg.GenerateKeypair();
        PrintPanel("Bob's Long-term Keys", [
            $":man: Bob Signature Public: {bSigPk.PrettyPrint()}",
            $":locked: Bob Signature Secret: {bSigSk.PrettyPrint()}"
        ]);

        PrintPanel("Step 2: Key Exchange", ["Alice generates KEM keypair and signs it"]);

        // A -> B: kem_pk, signature
        var (kemPk, kemSk) = kemAlg.GenerateKeypair();
        var signature1 = sigAlg.Sign(kemPk, aSigSk);
        PrintPanel("Alice → Bob", [
            $":key: KEM Public Key: {kemPk.PrettyPrint()}",
            $":pen: Alice's Signature: {signature1.PrettyPrint()}"
        ]);

        PrintPanel("Step 3: Encapsulation", ["Bob verifies Alice's signature and encapsulates a shared secret"]);

        // B -> A: kem_ct, signature
        if (!sigAlg.Verify(kemPk, signature1, aSigPk))
        {
            PrintPanel("Error", [":cross_mark: Failed to verify Alice's signature!"]);
            return;
        }

        var (kemCt, bKemSs) = kemAlg.Encapsulate(kemPk);
        var signature2 = sigAlg.Sign(kemCt, bSigSk);
        PrintPanel("Bob → Alice", [
            $":check_mark_button: Alice's signature verified",
            $":package: Ciphertext: {kemCt.PrettyPrint()}",
            $":pen: Bob's Signature: {signature2.PrettyPrint()}",
            $":closed_lock_with_key: Bob's Shared Secret: {bKemSs.PrettyPrint()}"
        ]);

        PrintPanel("Step 4: Decapsulation", ["Alice verifies Bob's signature and decapsulates the shared secret"]);

        // A verifies, decapsulates, now both have kem_ss
        if (!sigAlg.Verify(kemCt, signature2, bSigPk))
        {
            PrintPanel("Error", [":cross_mark: Failed to verify Bob's signature!"]);
            return;
        }

        var aKemSs = kemAlg.Decapsulate(kemSk, kemCt);
        PrintPanel("Alice's Result", [
            $":check_mark_button: Bob's signature verified",
            $":closed_lock_with_key: Alice's Shared Secret: {aKemSs.PrettyPrint()}"
        ]);

        // Verify shared secrets match
        var success = aKemSs.SequenceEqual(bKemSs);
        PrintPanel("Final Result", [
            $"{(success ? ":check_mark_button:" : ":cross_mark:")} Key exchange successful: {success}",
            $"Both parties now share a secure secret!"
        ]);
    }

    public static void RunAlgorithmComparison()
    {
        AnsiConsole.Write(new Rule("[yellow]Algorithm Comparison[/]").RuleStyle("yellow"));

        var table = new Table()
            .Border(TableBorder.Rounded)
            .AddColumn("Algorithm")
            .AddColumn("Type")
            .AddColumn("Enabled")
            .AddColumn("Key Sizes")
            .AddColumn("Security Level");

        // KEM algorithms
        foreach (var kemAlg in Enum.GetValues<KemAlgorithm>())
        {
            var enabled = kemAlg.IsEnabled();
            var keyInfo = "";
            if (enabled)
            {
                try
                {
                    using var kem = new KemInstance(kemAlg);
                    keyInfo = $"PK:{kem.PublicKeyLength} SK:{kem.SecretKeyLength} CT:{kem.CiphertextLength} SS:{kem.SharedSecretLength}";
                }
                catch
                {
                    keyInfo = "Error";
                }
            }

            var secLevel = kemAlg switch
            {
                KemAlgorithm.MlKem512 or KemAlgorithm.Kyber512 => "Level 1",
                KemAlgorithm.MlKem768 or KemAlgorithm.Kyber768 => "Level 3",
                KemAlgorithm.MlKem1024 or KemAlgorithm.Kyber1024 => "Level 5",
                _ when kemAlg.ToString().Contains("640") => "Level 1",
                _ when kemAlg.ToString().Contains("976") => "Level 3",
                _ when kemAlg.ToString().Contains("1344") => "Level 5",
                _ => "Various"
            };

            table.AddRow(
                kemAlg.ToString(),
                "KEM",
                enabled ? "[green]✓[/]" : "[red]✗[/]",
                keyInfo,
                secLevel
            );
        }

        // Signature algorithms
        foreach (var sigAlg in Enum.GetValues<SigAlgorithm>())
        {
            var enabled = sigAlg.IsEnabled();
            var keyInfo = "";
            if (enabled)
            {
                try
                {
                    using var sig = new SigInstance(sigAlg);
                    keyInfo = $"PK:{sig.PublicKeyLength} SK:{sig.SecretKeyLength} MaxSig:{sig.MaxSignatureLength}";
                }
                catch
                {
                    keyInfo = "Error";
                }
            }

            var secLevel = sigAlg switch
            {
                SigAlgorithm.MlDsa44 or SigAlgorithm.Dilithium2 or SigAlgorithm.Falcon512 => "Level 1",
                SigAlgorithm.MlDsa65 or SigAlgorithm.Dilithium3 => "Level 3",
                SigAlgorithm.MlDsa87 or SigAlgorithm.Dilithium5 or SigAlgorithm.Falcon1024 => "Level 5",
                _ when sigAlg.ToString().Contains("128") => "Level 1",
                _ => "Various"
            };

            table.AddRow(
                sigAlg.ToString(),
                "Signature",
                enabled ? "[green]✓[/]" : "[red]✗[/]",
                keyInfo,
                secLevel
            );
        }

        AnsiConsole.Write(table);
    }

    static void PrintPanel(string header, string[] data)
    {
        var content = string.Join(Environment.NewLine, data);
        var panel = new Panel(content)
        {
            Header = new PanelHeader($" {header} ")
        };
        AnsiConsole.Write(panel);
        AnsiConsole.WriteLine();
    }
}

public static class FormatExtensions
{
    public static string PrettyPrint(this byte[] bytes)
    {
        var base64 = Convert.ToBase64String(bytes);
        return base64.Length > 50 ? $"{base64[..25]}...{base64[^25..]}" : base64;
    }
}
