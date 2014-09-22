// СМЭВ подписывалка с помощью КриптоПро CSP - CryptoAPI Lite (CAPILite)
// Copyright (C) 2014 Denis Larionov

//    Важно:
//    Т.к. давно не программировал на C++ то затаскивать XML-парсер мне было тяжело
//    поэтому, подписывалку я реализовал в двухшаговом алгоритме:
//
//    Первый шаг: находится сертификат и вычисляется хеш полученного
//    буфера (нормализованного содержимого тега Body) и отсылаются обе эти части клиенту
//
//    Второй шаг: подписывается полученный буфер (нормализованное содержимое тега SignedInfo)
//
//    Оба этих действия я вызываю из стороннего сервиса.
//    Для краткости кода, все проверки на ошибки удалены.

//    Полезные ссылки:
//    Руководство программиста CryptoAPI Lite http://cpdn.cryptopro.ru/default.asp?url=content/capilite/html/Titul.html
//    Сервис проверки подписи СМЭВ http://smev.gosuslugi.ru/portal/services-tools.jsp
//    Методические рекомендации по разработке электронных сервисов и применению технологии электронной подписи при межведомственном электронном взаимодействии Версия 2.5.5 http://smev.gosuslugi.ru/portal/
//    Пример на подпись объекта функции хеширования и проверку подписи http://cpdn.cryptopro.ru/content/csp36/html/group___hash_example_SigningHash.html
//    Пример использования функции CryptAcquireContext http://cpdn.cryptopro.ru/content/csp36/html/group___acquire_example_CryptAcquireContextExample.html
//    Подпись сообщений SOAP для СМЭВ с использованием КриптоПро .NET - http://www.cryptopro.ru/blog/2012/05/16/podpis-soobshchenii-soap-dlya-smev-s-ispolzovaniem-kriptopro-net
//    Подпись сообщений SOAP для СМЭВ с использованием КриптоПро JCP - http://www.cryptopro.ru/blog/2012/07/02/podpis-soobshchenii-soap-dlya-smev-s-ispolzovaniem-kriptopro-jcp
//    Темы на форуме:
//    http://www.cryptopro.ru/forum2/default.aspx?g=posts&t=4689#post26735
//    http://www.cryptopro.ru/forum2/default.aspx?g=posts&t=6045#post37686
//    http://www.cryptopro.ru/forum2/Default.aspx?g=posts&t=3291#post17028
//    http://www.cryptopro.ru/forum2/default.aspx?g=posts&t=2962#post15559
//    http://www.cryptopro.ru/forum2/default.aspx?g=posts&t=7637#post49187
//    http://www.cryptopro.ru/forum2/default.aspx?g=posts&t=1999#post10499
//    Ruby:
//    http://habrahabr.ru/post/231261/
//    https://github.com/benoist/xmldsig
//    https://github.com/openlogic/signed_xml


//    // Usage:
//
//    // PART 1
//    char * outBuf = 0;
//    std::size_t outSize = 0;
//    char * signerKey = "CN Signer Name";
//
//    define MAX_BODY_SIZE 1024*1024
//    char inBuf [MAX_BODY_SIZE];
//    std::size_t inSize;
//
//    doGetCertificate((BYTE**)&outBuf, (DWORD &)outSize, signerKey);
//    doHashData((const BYTE*)inBuf, (const DWORD &)inSize, (BYTE**)&outBuf, (DWORD &)outSize, signerKey);
//
//    // PART 2
//    doSign((const BYTE*)inBuf, (const DWORD &)inSize, (BYTE**)&outBuf, (DWORD &)outSize, signerKey);


//******************************* Support Functions
bool openStore(HCERTSTORE & hStoreHandle, const std::string & storeName) {
    bool result = false;

    hStoreHandle = CertOpenSystemStore(0, storeName.c_str());
    if (hStoreHandle) {
        result = true;
    } else {
    }
    return result;
}

bool getCertificateContext(const HCERTSTORE hCertStore,
                           const std::string &keyName,
                           PCCERT_CONTEXT &pCertContext) {
    bool result = false;

    pCertContext = CertFindCertificateInStore(
        hCertStore,            // Дескриптор хранилища, в котором будет осуществлен поиск.
        TYPE_DER,              // Тип зашифрования. В этом поиске не используется.
        0,                     // dwFindFlags. Специальный критерий поиска.
        CERT_FIND_SUBJECT_STR, // Тип поиска. Задает вид поиска, который будет
        keyName.c_str(),       // pvFindPara. Выдает определенное значение поиска
        0);         // pCertContext равен NULL для первого вызова

    if (!pCertContext) {
    } else {
        result = true;
    }

    return result;
}

bool allocData(BYTE **pbEncodedBlob, DWORD cbEncodedBlob) {
    bool result = false;
    *pbEncodedBlob = new BYTE [cbEncodedBlob];
    if (*pbEncodedBlob) {
        result = true;
    }
    return result;
}

void freeData(BYTE **pbEncodedBlob) {
    if (pbEncodedBlob) {
        delete [] *pbEncodedBlob;
        *pbEncodedBlob = 0;
    }
}

bool freeCertContext(PCCERT_CONTEXT &pCertContext) {
    CertFreeCertificateContext(pCertContext);
    pCertContext = 0;
    return true;
}

bool closeStore(HCERTSTORE & hStoreHandle) {
    CertCloseStore(hStoreHandle, CERT_CLOSE_STORE_FORCE_FLAG);
    hStoreHandle = 0;
    return true;
}

bool freeKeyContext(HCRYPTPROV & hCryptProv) {
    CryptReleaseContext(hCryptProv, 0);
    hCryptProv = 0;
    return true;
}


//******************************* Main Functions PART 1

bool doGetCertificate(BYTE **pbEncodedBlob, DWORD &cbEncodedBlob,
                      const std::string &signerKeyName) {
    bool r = true;
    HCERTSTORE hStoreHandle = 0;
    PCCERT_CONTEXT pCertContext = 0;

    openStore(hStoreHandle, MY_STORE_NAME);
    getCertificateContext(hStoreHandle, signerKeyName, pCertContext);

    cbEncodedBlob = pCertContext->cbCertEncoded;
    allocData(pbEncodedBlob, cbEncodedBlob);
    memcpy(*pbEncodedBlob, pCertContext->pbCertEncoded, cbEncodedBlob);
    freeCertContext(pCertContext);
    closeStore(hStoreHandle);

    return r;
}

bool doHashData(const BYTE* pbContent, const DWORD & cbContent,
                      BYTE **pbEncodedBlob, DWORD &cbEncodedBlob,
                const std::string &signerKeyName) {
    bool r = true;
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    cbEncodedBlob = 0;
    BYTE         *pbHashSize = 0;
    DWORD        dwHashLen = sizeof(DWORD);

    // ГОСТ Р 34.11-94

    // Получение дескриптора контекста криптографического провайдера.
    r = CryptAcquireContext(
       &hProv,
       NULL,
       NULL,
       PROV_GOST_2001_DH,
       CRYPT_VERIFYCONTEXT);


    // Создание объекта функции хеширования.
    r = CryptCreateHash(
        hProv,
        CALG_GR3411,
        0,
        0,
        &hHash);


    // Хеширование байтовой строки.
    r = CryptHashData(
       hHash,
       pbContent,
       cbContent,
       0);


    pbHashSize =(BYTE *) malloc(dwHashLen);

    r = CryptGetHashParam(hHash,
            HP_HASHSIZE,
            pbHashSize,
            &dwHashLen,
            0);


    if(pbHashSize)
      delete pbHashSize;

    r = CryptGetHashParam(hHash,
        HP_HASHVAL,
        NULL,
        &dwHashLen,
        0);


    allocData(pbEncodedBlob, dwHashLen);
    cbEncodedBlob = dwHashLen;
    r = CryptGetHashParam(
            hHash,
            HP_HASHVAL,
            *pbEncodedBlob,
            &dwHashLen,
            0);

    CryptDestroyHash(hHash);
    freeKeyContext(hProv);

    return r;
}


//******************************* Main Functions PART 1
bool doSign(const BYTE* pbContent, const DWORD & cbContent,
                  BYTE **pbSignBlob, DWORD &cbSignBlob,
                  const std::string &signerKey) {

    HCERTSTORE hStoreHandle = 0;
    PCCERT_CONTEXT pCertContext = 0;
    DWORD           keytype = AT_KEYEXCHANGE;
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    DWORD cbHash;
    BYTE *pbHash = NULL;
    BOOL                        bReleaseContext;
    bool r = true;
    DWORD dwSigLen;

    r = openStore(hStoreHandle, MY_STORE_NAME);
    r = getCertificateContext(hStoreHandle, signerKey, pCertContext);
    r = CryptAcquireCertificatePrivateKey(pCertContext,
                0,
                NULL,
                &hProv,
                &keytype,
                &bReleaseContext);

    r = CryptCreateHash(
        hProv,
        CALG_GR3411,
        0,
        0,
        &hHash);

    // Вычисление криптографического хеша буфера.
    r = CryptHashData(
            hHash,
            pbContent,
            cbContent,
            0);

    // Определение размера подписи и распределение памяти.
    r = CryptSignHash(
            hHash,
// ВНИМАНИЕ!!! В примере из документации используется другое значение константы
// На самом деле она зависит от типа ключа, который зарегистрирован в хранилище
            AT_KEYEXCHANGE, // AT_SIGNATURE,
            NULL,
            0,
            NULL,
            &cbSignBlob);

    allocData(pbSignBlob, cbSignBlob);
    r = CryptSignHash(
        hHash,
// ВНИМАНИЕ!!! В примере из документации используется другое значение константы
// На самом деле она зависит от типа ключа, который зарегистрирован в хранилище
//
        AT_KEYEXCHANGE, // AT_SIGNATURE,
        NULL,
        0,
        *pbSignBlob,
        &cbSignBlob);


    BYTE exchange = 0;
    // http://www.cryptopro.ru/forum2/default.aspx?g=posts&t=4689#post26735
    // А теперь фокус! Нужно изменить порядок байтов в подписи на противоположный. Не спрашивайте почему - не знаю. Интимная связь между CSP и JCP :)
    for( int i=0; i < (cbSignBlob/2); i++ ) {
        exchange = (*pbSignBlob)[64-i-1];
        (*pbSignBlob)[64-i-1]=(*pbSignBlob)[i];
        (*pbSignBlob)[i] = exchange;
    }

    freeCertContext(pCertContext);
    closeStore(hStoreHandle);
    CryptDestroyHash(hHash);
    freeKeyContext(hProv);

    return r;
}
