using SMBLibrary;
using SMBLibrary.Client.Helpers;
using SMBLibrary.RPC;
using SMBLibrary.Services;
using System;

/// <summary>
/// rQueryServiceStatus   Request (opnum 06)
/// </summary>
public class rQueryServiceStatusRequest : IRPCRequest
{
    public LPSC_RPC_HANDLE hService;

    public rQueryServiceStatusRequest()
    {
    }

    public byte[] GetBytes()
    {
        NDRWriter writer = new NDRWriter();
        //writer.WriteEmbeddedStructureFullPointer(null);
        writer.WriteStructure(hService);
        return writer.GetBytes();
    }
}
public class rDeleteServiceRequest : IRPCRequest
{
    public LPSC_RPC_HANDLE hService;

    public rDeleteServiceRequest()
    {
    }

    public byte[] GetBytes()
    {
        NDRWriter writer = new NDRWriter();
        writer.WriteStructure(hService); // Serialize the service context handle
        return writer.GetBytes();
    }
}