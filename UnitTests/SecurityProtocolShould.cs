using RSBot.Core;
using RSBot.Core.Extensions;
using RSBot.Core.Network;
using RSBot.Core.Network.Protocol;
using System.IO;
using System.Net.Sockets;

namespace UnitTests
{
    [TestClass]
    public sealed class SecurityProtocolShould
    {
        [TestMethod]
        public async Task Recv_SmokeTest()
        {
            // ennyi erovel Packet-t is be lehetne kuldeni a megfelelo handler peldanyositas elott
            // => sajat bot irashoz kellene ez
            // kellene egy fajl, abbol beolvasni packetokat, kell a szunet kozottuk
            // Setup
            // kliens szerverrol van szo
            // amugy jo lenne egy Packet lista. (puding probaja eves lesz, de inkabb allapotgep teszt lesz ez)
            // statikus Packet lista, kozottuk kesleltetesekkel
            // clientless, S->C kommunikacion alapszik az egesz, a szerveren is fut egy program, egy masik amihez a kliens csatlakozik. Amit en jateknak hivok ketto gep kozotti vezeteken szaladgalo feszultseg szintek, es annak valtogatasa...ha TCP socket-en megfelelo packetok mennek akkor a jatek "megy".
            // ez a BE

            // es a front-end...: rajzolasok, 2D 3D, vonalak, terhatas keltese szinekkel egy 2D-s vasznon


            // Network handlers/hooks
            Kernel.Initialize();

            var pck = new Packet(0xB0BD);
            pck.WriteUInt(1);
            pck.WriteUInt(2);
            pck.WriteUInt(3);
            pck.Lock();
            var bytes = pck.GetBytes();

            Stream outp = new MemoryStream();
            var writer = new BinaryWriter(outp);
            writer.Write((ushort)pck.Length);
            writer.Write((ushort)pck.Opcode);
            // security count
            writer.Write((byte)0);
            // crc
            writer.Write((byte)0);
            writer.Write(bytes);

            var buffer = writer.GetSnapshot();

            var svc = new SecurityProtocol();

            // Act
            svc.Recv(buffer, 0, buffer.Length);

            var packets = svc.TransferIncoming();
            for (int i = 0; i < packets.Count; i++)
            {
                Packet? packet = packets[i];
                // when destination is client = S -> C
                packet = PacketManager.CallHook(packet, PacketDestination.Client);
                if (packet != null)
                {
                    PacketManager.SendPacket(packet, PacketDestination.Client);

                    packet.SeekRead(0, SeekOrigin.Begin);

                    PacketManager.CallHandler(packet, PacketDestination.Client);
                    PacketManager.CallCallback(packet);
                }
            }
        }
    }
}
