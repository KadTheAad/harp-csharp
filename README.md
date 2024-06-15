# HARP (Written in C#)

HARP-C# is a C# library for resolving local IPv4 addresses securely.

## Installation

1. Then download the latest release from [releases](https://github.com/KadTheAad/harp-cs/releases).
2. Import the DLL into your IDE.

## Usage
All interfacing with the library can be done through the Harp class. This is how to use Harp:
```c#
class Callback : HarpCallback
{
    // This method is called during the second phase of the Harp protocol
    public override void Phase2(IPAddress address, VerifyPacket packet)
    {
        Console.WriteLine("Phase 2: " + address);
    }

    // This method is called when the Harp protocol has completed
    public override void Run(IPAddress address)
    {
        Console.WriteLine("Run: " + address);
    }
}
// Main entry point of the program
public static void Main(string[] args)
{
    // Create a new Harp instance for sender
    Harp harp = new Harp(true, Encoding.UTF8.GetBytes("1"), Encoding.UTF8.GetBytes("2"), "1234",
        new Callback());
    // Create a new Harp instance for reciever
    Harp harp2 = new Harp(false, Encoding.UTF8.GetBytes("2"), Encoding.UTF8.GetBytes("1"), "1234",
        new Callback());
    // Run the Harp protocol on both instances
    harp.Run();
    harp2.Run();
}
```

## Contributing

Pull requests are welcome. For major changes, please open an issue first
to discuss what you would like to change.

## License

[GNU LGPLv3](https://choosealicense.com/licenses/lgpl-3.0/)
