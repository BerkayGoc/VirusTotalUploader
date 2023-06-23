using VirusTotalNet;
using VirusTotalNet.ResponseCodes;
using VirusTotalNet.Results;

internal class Program
{
    public static async Task Main(string[] args)
    {
        if (args.Length > 0)
        {
            string pathFile = args[0];
            Console.WriteLine($"File: {pathFile}");
            await UploadToVt(pathFile);
            Console.ReadKey();
        }
    }

    private static async Task UploadToVt(string pathFile)
    {
        VirusTotal virusTotal = new VirusTotal("eb015ebe48ed47704fde249b1beaa1331c5710a86863f3c08d805f42b2773b5d");
        virusTotal.UseTLS = true;
        byte[] eicar = await ConvertFileToBytes(pathFile);

        FileReport report = await virusTotal.GetFileReportAsync(eicar);

        Console.WriteLine("Seen before: " + (report.ResponseCode == FileReportResponseCode.Present ? "Yes" : "No"));
        Console.WriteLine("ScanID: " + report.ScanId);
        Console.WriteLine("Positives: " + report.Positives);
        Console.WriteLine("Total: " + report.Total);
        Console.WriteLine("Message: " + report.VerboseMsg);
    }

    private static async Task<byte[]> ConvertFileToBytes(string fileName)
    {
        await using FileStream fs = new FileStream(fileName, FileMode.Open, FileAccess.Read);
        var buffer = new byte[fs.Length];
        int _ = fs.Read(buffer, 0, (int)fs.Length);
        return buffer;
    }
}