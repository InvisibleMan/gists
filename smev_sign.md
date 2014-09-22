# СМЭВ подписывалка с помощью КриптоПро CSP - CryptoAPI Lite (CAPILite)

## Важно:
Т.к. давно не программировал на C++ то затаскивать XML-парсер мне было тяжело поэтому, подписывалку я реализовал в двухшаговом алгоритме:

* Первый шаг: находится сертификат и вычисляется хеш полученного буфера (нормализованного содержимого тега Body) и отсылаются обе эти части клиенту
* Второй шаг: подписывается полученный буфер (нормализованное содержимое тега SignedInfo)

**Оба этих действия я вызываю из стороннего сервиса. Для краткости кода, все проверки на ошибки удалены.**

## Полезные ссылки:
**Документация:**
* [Руководство программиста CryptoAPI Lite](http://cpdn.cryptopro.ru/default.asp?url=content/capilite/html/Titul.html)
* [Сервис проверки подписи СМЭВ](http://smev.gosuslugi.ru/portal/services-tools.jsp)
* [Методические рекомендации по разработке электронных сервисов и применению технологии электронной подписи при межведомственном электронном взаимодействии Версия 2.5.5](http://smev.gosuslugi.ru/portal/)

**Примеры:**
* [Пример на подпись объекта функции хеширования и проверку подписи](http://cpdn.cryptopro.ru/content/csp36/html/group___hash_example_SigningHash.html)
* [Пример использования функции CryptAcquireContext](http://cpdn.cryptopro.ru/content/csp36/html/group___acquire_example_CryptAcquireContextExample.html)
* [Подпись сообщений SOAP для СМЭВ с использованием КриптоПро .NET](http://www.cryptopro.ru/blog/2012/05/16/podpis-soobshchenii-soap-dlya-smev-s-ispolzovaniem-kriptopro-net)
* [Подпись сообщений SOAP для СМЭВ с использованием КриптоПро JCP](http://www.cryptopro.ru/blog/2012/07/02/podpis-soobshchenii-soap-dlya-smev-s-ispolzovaniem-kriptopro-jcp)

**Темы на форуме:**
* <http://www.cryptopro.ru/forum2/default.aspx?g=posts&t=4689#post26735>
* <http://www.cryptopro.ru/forum2/default.aspx?g=posts&t=6045#post37686>
* <http://www.cryptopro.ru/forum2/Default.aspx?g=posts&t=3291#post17028>
* <http://www.cryptopro.ru/forum2/default.aspx?g=posts&t=2962#post15559>
* <http://www.cryptopro.ru/forum2/default.aspx?g=posts&t=7637#post49187>
* <http://www.cryptopro.ru/forum2/default.aspx?g=posts&t=1999#post10499>

**Ruby:**
* <http://habrahabr.ru/post/231261/>
* <https://github.com/benoist/xmldsig>
* <https://github.com/openlogic/signed_xml>

## Пример использования
```c
// Usage:
//
// PART 1
char * outBuf = 0;
std::size_t outSize = 0;
char * signerKey = "CN Signer Name";
//
define MAX_BODY_SIZE 1024*1024
char inBuf [MAX_BODY_SIZE];
std::size_t inSize;
//
doGetCertificate((BYTE**)&outBuf, (DWORD &)outSize, signerKey);
doHashData((const BYTE*)inBuf, (const DWORD &)inSize, (BYTE**)&outBuf, (DWORD &)outSize, signerKey);
//
// PART 2
doSign((const BYTE*)inBuf, (const DWORD &)inSize, (BYTE**)&outBuf, (DWORD &)outSize, signerKey);
```

Copyright (C) 2014 Denis Larionov