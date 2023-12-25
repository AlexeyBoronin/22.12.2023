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