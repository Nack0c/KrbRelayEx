using SMBLibrary.RPC;
using SMBLibrary.Services;

/// <summary>
/// rQueryServiceStatus   Response (opnum 06)
/// </summary>
public class rQueryServiceStatusResponse
{
    public SERVICE_STATUS lpServiceStatus;

    public rQueryServiceStatusResponse(byte[] buffer)
    {
        NDRParser parser = new NDRParser(buffer);

        parser.BeginStructure();
        lpServiceStatus = new SERVICE_STATUS();
        parser.ReadStructure(lpServiceStatus);
        parser.EndStructure();
    }
}
public class rDeleteServiceResponse
{
    public void FromBytes(byte[] buffer, ref int offset)
    {
        // No fields to parse; NTSTATUS is returned out-of-band
    }
}