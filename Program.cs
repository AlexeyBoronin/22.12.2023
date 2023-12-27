//System.Net
/* System.Net.Http - функиональность по работе с протокол HTTP
 * System.Net.NetworkInformation - содержит информацию о сетевом трафике и сетевых адрес, а так о прочей инфорации о хостах сети. Плюс функцианольность ping.
 * System.Net.Security - сетевоые потоки для безопасной связи между хостами
 * System.Net.Sockets - взаимодействие с сокетами ОП
 * System.Net.webSockets - реализация интерфейса WebSocket
 * System.Net.Quic - содержит типы, коорые реализуют протокол QUIC в соответствии со спецификацией RFC 9000.
 */
//Адреса в .Net
//IPAddress
/* public IPAddress(byte[] address);
 * public IPAddress(Long newAddress);
 */
using System.Net;
using System.Net.NetworkInformation;

IPAddress localIp = new IPAddress(new byte[] { 127, 0, 0, 1 });
Console.WriteLine(localIp);

IPAddress someIp = new IPAddress(0x0100007F);
Console.WriteLine(someIp);
IPAddress.TryParse("127.0.0.11", out IPAddress? ip);
Console.WriteLine(ip?.ToString());
//Встроенные адреса
/* Loopback - возращает объект IPAddress для адреса 127.0.0.1
 * Any - возращает объект IPAddress для адреса 0.0.0.0
 * Broadcast - возращает объект IPAddress для адреса 255.255.255.255
 */
IPAddress anyIp = IPAddress.Any;
IPAddress localIp1 = IPAddress.Loopback;
IPAddress broadcastIp= IPAddress.Broadcast;
Console.WriteLine(broadcastIp?.ToString());
Console.WriteLine(localIp1?.ToString());
Console.WriteLine(anyIp?.ToString());
//Схема адресации AddresFamily
/*AppleTalk: адрес AppleTalk
Atm: адрес собственных служб ATM
Banyan: адрес Banyan
Ccitt: адреса протоколов CCITT, таких как протокол X25
Chaos: адрес протоколов MIT CHAOS
Cluster: адрес кластерных продуктов корпорации Майкрософт
ControllerAreaNetwork: сетевой адрес области контроллера
DataKit: адрес протоколов Datakit
DataLink: адрес интерфейса прямого канала передачи данных
DecNet: адрес DECnet
Ecma: адрес ЕСМА (European Computer Manufacturers Association — европейская ассоциация производителей компьютеров)
FireFox: адрес FireFox
HyperChannel: адрес NSC Hyperchannel
Ieee12844: адрес рабочей группы IEEE 12844
ImpLink: адрес ARPANET IMP
InterNetwork: IPv4-адрес
InterNetworkV6: IPv6-адрес
Ipx: IPX- или SPX-адрес
Irda: IrDA-адрес
Iso: адрес протоколов ISO
Lat: LAT-адрес
Max: MAX-адрес
NetBios: адрес NetBios
NetworkDesigners: адрес шлюзовых протоколов Network Designers OSI
NS: адрес протоколов Xerox NS
Osi: адрес протоколов OSI
Packet: адрес пакета нижнего уровня
Pup: адрес протоколов PUP
Sna: адрес IBM SNA
Unix: локальный адрес Unix для узла
Unknown: семейство неизвестных адресов
Unspecified: семейство неуказанных адресов
VoiceView: адрес VoiceView
 */
IPAddress localIP = new IPAddress(new byte[] { 127, 0, 0, 1 });
Console.WriteLine(localIP.AddressFamily);
//Конечная точка IPEndpoint
/*public IPendpoint(long address, int port);
 * public IPEndpoint(IPAddress address, int point);
 */
IPAddress ip1=IPAddress.Parse("127.0.0.1");
IPEndPoint endpoint = new IPEndPoint(ip1, 8080);
Console.WriteLine(endpoint);
//Адреса URI - Uniform Resourse Identifier
Uri uri =new Uri("https://www.google.com/search?q=%D0%BA%D0%BE%D0%BC%D0%BC%D1%83%D1%82%D0%B0%D1%82%D0%BE%D1%80+3+%D1%83%D1%80%D0%BE%D0%B2%D0%BD%D1%8F+%D1%81+%D0%BE%D0%BF%D1%82%D0%BE%D0%B2%D0%BE%D0%BB%D0%BE%D0%BA%D0%BD%D0%BE%D0%BC&tbm=isch&ved=2ahUKEwjkqpeIraODAxVCFBAIHSYnCKoQ2-cCegQIABAA&oq=%D0%BA%D0%BE%D0%BC%D0%BC%D1%83%D1%82%D0%B0%D1%82%D0%BE%D1%80+3+%D1%83%D1%80%D0%BE%D0%B2%D0%BD%D1%8F+%D1%81+%D0%BE%D0%BF%D1%82%D0%BE%D0%B2%D0%BE%D0%BB%D0%BE%D0%BA%D0%BD%D0%BE%D0%BC&gs_lcp=CgNpbWcQA1DtCVjyCmDcF2gAcAB4AIABRogBvgGSAQEzmAEAoAEBqgELZ3dzLXdpei1pbWfAAQE&sclient=img&ei=P6qFZaSPGMKowPAPps6g0Ao&bih=1279&biw=2560");
Console.WriteLine($"AbsolutePath : {uri.AbsolutePath}");
Console.WriteLine($"AbsoluteUri : {uri.AbsoluteUri}");
Console.WriteLine($"Fragment : {uri.Fragment}");
Console.WriteLine($"Host : {uri.Host}");
Console.WriteLine($"IsAbsoluteUri : {uri.IsAbsoluteUri}");
Console.WriteLine($"IsDefaultPort :{uri.IsDefaultPort}");
Console.WriteLine($"IsFile :{uri.IsFile}");
Console.WriteLine($"IsLoopback :{uri.IsLoopback}");
Console.WriteLine($"OriginalString :{uri.OriginalString}");
Console.WriteLine($"PathAndQuery :{uri.PathAndQuery}");
Console.WriteLine($"Port :{uri.Port}");
Console.WriteLine($"Query :{uri.Query}");
Console.WriteLine($"Scheme :{uri.Scheme}");
Console.WriteLine($"Segments :{string.Join(",",uri.Segments)}");
Console.WriteLine($"UserInfo :{uri.UserInfo}");
Console.WriteLine();
//UriKind
Uri uri1 = new Uri("https://yandex.ru", UriKind.Absolute);
Uri uri2 = new Uri("maps", UriKind.Relative);
Uri uri3 = new Uri("https://yandex.ru/maps", UriKind.RelativeOrAbsolute);

string url = "sSADFG";
if (Uri.TryCreate(url, new UriCreationOptions(), out Uri? newUri))
{
    Console.WriteLine($"Uri создан: {newUri.OriginalString}");
}
else
    Console.WriteLine("невозможно создать URI. некорректынй адрес");
//DNS
/* GetHostAddress(string hostNameOrAddress) - запрашивает DNS-сервер и возращает все ip-фдреса для определенного имени хоста в виде массива 
 * System.Net.IPAddress[]. Данный метод имеет асинхронного двойника в виде метода GetHostAddressAsync(string hostNameOrAddress)
 * GetHostEntry(string hostNameOrAddress) - запрашивает DNS-сервер и возращает объект IPHostEntry для определенного имени хоста или ip-адреса. 
 * Данный метод имеет асинхронного двойника в виде метода GetHostAddressAsync(string hostNameOrAddress)
 * GetHostName() - возвращает имя хоста локального компьютера
 */
var googleEntry = await Dns.GetHostEntryAsync("google.com");
Console.WriteLine(googleEntry.HostName);
foreach(var ip2 in googleEntry.AddressList)
    Console.WriteLine(ip2);
var googleIps = await Dns.GetHostAddressesAsync("google.com");
foreach( var ip2 in googleIps)
{ Console.WriteLine(ip2); }
//Получение информации о сетевой конфигурации и сетевом трафике
//NetworkInterface и сетевые устройства
/* Description: возвращает описание сетевого интерфейса
*  Id: возвращает идентификатор сетевого адаптера
*  Name: возвращает название сетевого адаптера
*  NetworkInterfaceType: тип сетевого интерефейса в виде константы перечисления System.Net.NetworkInformation.NetworkInterfaceType
*  OperationalStatus: возвращает текущий статус операций в виде
*  Speed: возвращает скорость сетевого адаптера в виде количества битов в секунду
*  
*  GetAllNetworkInterfaces(): возвращает массив объектов NetworkInterface, где каждый элемент представляет 
*  сетевой интерфейс на локальной машине (статический метод)
*  GetIPProperties(): возвращает объект IPInterfaceProperties, который представляет все свойства сетевого интерфейса
*  GetIPStatistics(): возвращает статистику для текущего сетевого интерфейса в виде объекта , который хранит статистику в свойствах:
*  BytesReceived: возвращает количество байтов, полученных интерфейсом.
*  BytesSent: возвращает количество байтов, отправленных интерфейсом.
*  IncomingPacketsDiscarded: возвращает количество входящих пакетов, которые были удалены.
*  IncomingPacketsWithErrors: возвращает количество входящих пакетов с ошибками.
*  IncomingUnknownProtocolPackets: возвращает количество входящих пакетов с неизвестным протоколом, которые были получены в интерфейсе.
*  NonUnicastPacketsReceived: возвращает количество неодноадресных пакетов, полученных интерфейсом.
*  NonUnicastPacketsSent: возвращает количество неодноадресных пакетов, отправленных интерфейсом
*  OutgoingPacketsDiscarded: возвращает количество исходящих пакетов, которые были удалены.
*  OutgoingPacketsWithErrors: возвращает количество исходящих пакетов с ошибками
*  OutputQueueLength: возвращает длину очереди вывода.
*  UnicastPacketsReceived: возвращает количество одноадресных пакетов, полученных интерфейсом.
*  UnicastPacketsSent: возвращает количество одноадресных пакетов, отправленных интерфейсом.
*  GetIsNetworkAvailable(): возвращает true, если доступно какое-либо сетевое подключение (статический метод)
*  GetPhysicalAddresss(): возвращает физический адрес сетевого интерфейса
 */
var adapter=NetworkInterface.GetAllNetworkInterfaces();
Console.WriteLine($"Обнаружено {adapter.Length} устройств");
foreach(NetworkInterface ad in adapter)
{
    Console.WriteLine("=================================");
    Console.WriteLine();
    Console.WriteLine($"Устройство ID -------- {ad.Id}");
    Console.WriteLine($"Устройство имя -------- {ad.Name}");
    Console.WriteLine($"Описание: ---------{ad.Description}");
    Console.WriteLine($"Тип интерфейса: ---------{ad.NetworkInterfaceType}");
    Console.WriteLine($"Тип интерфейса: ---------{ad.NetworkInterfaceType}");
    Console.WriteLine($"Физический адрес: ---------{ad.GetPhysicalAddress()}");
    Console.WriteLine($"Статус: ---------- {ad.OperationalStatus}");
    Console.WriteLine($"Скорость: ------{ad.Speed}");
    IPInterfaceStatistics stats=ad.GetIPStatistics();
    Console.WriteLine($"Получено: ---------------{stats.BytesReceived}");
    Console.WriteLine($"Отправлено: ---------------{stats.BytesSent}");

}
//Получение информации о всех подключениях
/* GetActiveTcpConnections(): возвращает сведения о TCP-подключениях (массив TcpConnectionInformation[])
*  GetActiveTcpListeners(): возвращает массив адресов TCP-слушателей (массив IPEndPoint[])
*  GetActiveUdpListeners(): возвращает массив адресов UDP-слушателей (массив IPEndPoint[]).
*  GetIcmpV4Statistics(): возвращает статистику протокола ICMPv4 (объект IcmpV4Statistics)
*  GetIcmpV6Statistics(): возвращает статистику протокола ICMPv6 (объект IcmpV6Statistics)
*  GetIPv4GlobalStatistics(): возвращает статистику протокола IPv4 (объект IPGlobalStatistics)
*  GetIPv6GlobalStatistics(): возвращает статистику протокола IPv6 (объект IPGlobalStatistics)
*  GetIPGlobalProperties(): возвращает объект IPGlobalProperties, который предоставляет информацию по сетевой 
конфигурации и статистику трафика (статический метод)
*  GetUnicastAddresses() / GetUnicastAddressesAsync(): возвращает таблицу IP-адресов одноадресной рассылки (объект UnicastIPAddressInformationCollection)
 */
var IpProps=IPGlobalProperties.GetIPGlobalProperties();
var tcpConnections=IpProps.GetActiveTcpConnections();
Console.WriteLine($"Всего {tcpConnections.Length} активных TCP-подключений");
Console.WriteLine();
foreach(var connection in tcpConnections)
{
    Console.WriteLine("============================");
    Console.WriteLine($"Локальный адрес: {connection.LocalEndPoint.Address}:{connection.LocalEndPoint.Port}");
    Console.WriteLine($"Адрес удаленного хоста: {connection.RemoteEndPoint.Address}:{connection.RemoteEndPoint.Port}");
    Console.WriteLine($"Состояние подключения: {connection.State}");
}
/* LocalEndPoint: локальная конечная точка, через которую текущий компьютер установил TCP-подключение с удаленным хостом
*  RemoteEndPoint: адрес удаленного хоста, с которым установлено TCP-подключение
*  State: состояние TCP-подключения в виде одной из констант перечисления TcpState:
*  Closed: TCP-подключение закрыто
*  CloseWait: локальная конечная точка ТСР-подключения ожидает от локального пользователя запрос на разрыв подключения
*  Closing: локальная конечная точка ТСР-подключения ожидает подтверждение ранее отправленного запроса на разрыв подключения
*  DeleteTcb: удаляется буфер управления передачей (TCB) для ТСР-подключения
*  Established: TCP-подключение установлено.
*  FinWait1: локальная конечная точка ТСР-подключения ожидает от удаленной конечной точки запрос на разрыв подключения или подтверждение 
ранее отправленного запроса на разрыв подключения.
*  FinWait2: локальная конечная точка ТСР-подключения ожидает от удаленной конечной точки запрос на разрыв подключения.
*  LastAck: локальная конечная точка ТСР-подключения ожидает окончательное подтверждение ранее отправленного запроса на разрыв подключения.
*  Listen: локальная конечная точка ТСР-подключения прослушивает запросы на подключение
*  SynReceived: локальная конечная точка ТСР-подключения отправила и получила запрос на подключение, и ожидает подтверждения.
*  SynSent: локальная конечная точка ТСР-подключения отправила удаленной конечной точке заголовок сегмента с установленным управляющим битом
синхронизации (SYN) и ожидает соответствующий запрос на подключение.
*  TimeWait: локальная конечная точка ТСР-подключения ожидает в течение достаточного времени, чтобы обеспечить получение удаленной точкой 
подтверждения ее запроса на разрыв подключения.
*  Unknown: неизвестное состояние ТСР-подключения
 */
//Мониторинг трафика
/* DefaultTtl: возвращает срок жизни (TTL) IP-пакетов.
*  ForwardingEnabled: возвращает значение bool, которое указывает, разрешена ли переадресация IP-пакетов.
*  NumberOfInterfaces: возвращает количество сетевых интерфейсов.
*  NumberOfIPAddresses: возвращает количество IP-адресов, назначенных локальному компьютеру.
*  NumberOfRoutes: возвращает количество маршрутов в таблице IP-маршрутизации.
*  OutputPacketRequests: возвращает количество исходящих IP-пакетов.
*  OutputPacketRoutingDiscards: возвращает количество маршрутов, удаленных из таблицы маршрутизации.
*  OutputPacketsDiscarded: возвращает количество отправленных отброшенных IP-пакетов
*  OutputPacketsWithNoRoute: возвращает количество IP-пакетов, для которых локальному компьютеру не удалось определить маршрут к адресу назначения.
*  PacketFragmentFailures: возвращает количество IP-пакетов, которые не удалось фрагментировать.
*  PacketReassembliesRequired: возвращает количество IP-пакетов, для которых требовалась восстановление.
*  PacketReassemblyFailures: возвращает количество IP-пакетов, которые не были успешно восстановлены.
*  PacketReassemblyTimeout: возвращает максимальное время, в течение которого должны поступить все фрагменты IP-пакета.
*  PacketsFragmented: возвращает количество фрагментированных IP-пакетов.
*  PacketsReassembled: возвращает количество собранных IP-пакетов.
*  ReceivedPackets: возвращает количество полученных IP-пакетов.
*  ReceivedPacketsDelivered: возвращает количество доставленных IP-пакетов.
*  ReceivedPacketsDiscarded: возвращает количество отброшенных полученных IP-пакетов, которые были удалены.
*  ReceivedPacketsForwarded: возвращает количество переадресованных IP-пакетов.
*  ReceivedPacketsWithAddressErrors: возвращает количество полученных IP-пакетов с ошибками в адресе.
*  ReceivedPacketsWithHeadersErrors: возвращает количество полученных IP-пакетов с ошибками в заголовке.
*  ReceivedPacketsWithUnknownProtocol: возвращает количество IP-пакетов с неизвестным протоколом в заголовке, полученных локальным компьютером
 */
var IPProps=IPGlobalProperties.GetIPGlobalProperties();
var IpStats=IPProps.GetIPv4GlobalStatistics();
Console.WriteLine($"Входящие пакеты: {IpStats.ReceivedPackets}");
Console.WriteLine($"Исходящие пакеты: {IpStats.OutputPacketRequests}") ;
Console.WriteLine($"Отброшено входящих пакетов:{IpStats.ReceivedPacketsDiscarded}");
Console.WriteLine($"Отброшено исходящих пакетов: {IpStats.OutputPacketsDiscarded}") ;
Console.WriteLine($"Ошибки фрагментации: {IpStats.PacketFragmentFailures}");
Console.WriteLine($"Ошибки восстановления пакетов: {IpStats.PacketReassemblyFailures}") ;
//Класс Socket
/* Socket(AddressFamily, SocketType, ProtocolType): создает сокет, используя указанные семейство адресов, тип сокета и протокол.
*  Socket(SafeSocketHandle): создает сокет с помощью дескриптора сокета - объекта SafeSocketHandle.
*  Socket(SocketInformation): создает сокет, используя структуру SocketInformation.
*  Socket(SocketType, ProtocolType): создает сокет, используя указанные тип сокета и протокол.
*  
*  Первый параметр конструктора представляет перечисление AddressFamily и задает схему адресации, которую может использовать сокет. 
Данное перечисление содержит 33 константы. Наиболее используемые:
*  1.InterNetwork: адрес по протоколу IPv4
*  2.InterNetworkV6: адрес по протоколу IPv6
*  3.Ipx: адрес IPX или SPX
*  4.NetBios: адрес NetBios
*  Второй параметр представляет перечисление SocketType, которое устанавливает тип сокета. Может принимать следующие значения:
*  1.Dgram: сокет будет получать и отправлять дейтаграммы по протоколу Udp. Данный тип сокета работает в связке с типом протокола - Udp 
и значением AddressFamily.InterNetwork
*  2.Raw: сокет имеет доступ к нижележащему протоколу транспортного уровня и может использовать для передачи сообщений такие протоколы, как ICMP и IGMP
*  3.Rdm: сокет может взаимодействовать с удаленными хостами без установки постоянного подключения. В случае, если отправленные сокетом сообщения невозможно 
доставить, то сокет получит об этом уведомление
*  4.Seqpacket: обеспечивает надежную двустороннюю передачу данных с установкой постоянного подключения
*  5.Stream: обеспечивает надежную двустороннюю передачу данных с установкой постоянного подключения. Для связи используется протокол TCP, поэтому этот тип 
сокета используется в паре с типом протокола Tcp и значением AddressFamily.InterNetwork
*  6.Unknown: адрес NetBios
*  Третий параметр представляет перечисление ProtocolType, которое устанавливает тип используемого протокола. Может принимать следующие значения:
*  1.Ggp
*  2.Icmp
*  3.IcmpV6
*  4.Idp
*  5.Igmp
*  6.IP
*  7.IPSecAuthenticationHeader (Заголовок IPv6 AH)
*  8.IPSecEncapsulatingSecurityPayload (Заголовок IPv6 ESP)
*  9.IPv4
*  10.IPv6
*  11.IPv6DestinationOptions (Заголовок IPv6 Destination Options)
*  12.IPv6FragmentHeader (Заголовок IPv6 Fragment)
*  13.IPv6HopByHopOptions (Заголовок IPv6 Hop by Hop Options)
*  14.IPv6NoNextHeader (Заголовок IPv6 No next)
*  15.IPv6RoutingHeader (Заголовок IPv6 Routing)
*  16.Ipx
*  17.ND
*  18.Pup
*  19.Raw
*  20.Spx
*  21.SpxII
*  22.Tcp
*  23.Udp
*  24.Unknown (неизвестный протокол)
*  25.Unspecified (неуказанный протокол)
 */