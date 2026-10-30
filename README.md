# Retmon-EMS-Kimlik-Dogrulamasiz-Firmware-Yukleme

**CVSS 3.1 9.8 (Kritik)** · CWE-306 — Missing Authentication for Critical Function · Retmon EMS (DCT-200 Terminal)

## Genel Bakış

Retmon EMS, Retmon'un ortam izleme (Environmental Monitoring) çözümüdür; sıcaklık, nem ve benzeri çevresel değerleri izlemek amacıyla veri merkezleri, üretim tesisleri ve kritik altyapılarda kullanılır. İzleme, DCT-200 (Data Collection Terminal) adı verilen gömülü bir terminal cihazı üzerinde çalışır.

Cihaz üzerinde iki ayrı web servisi çalışır. TCP/80 portundaki ana EMS yönetim arayüzü oturum açma (kullanıcı adı/parola) gerektirirken, cihazın firmware'ini değiştirmeye yarayan TCP/8080 portundaki yükseltme servisi hiçbir kimlik doğrulaması istemez. Sonuç olarak, ağa erişen kimliği doğrulanmamış bir kişi cihaza firmware yükleyebilir.

| Servis | Port | Kimlik doğrulama |
|---|---|---|
| Ana EMS yönetim arayüzü | TCP/80 | Var (kullanıcı adı / parola) |
| Firmware yükseltme servisi | TCP/8080 | Yok |

## Teknik Detay

### Firmware yükseltme servisi kimlik doğrulaması istemiyor

TCP/8080 portundaki Node.js/Express tabanlı servis, yükseltme arayüzünü ve ilgili uç noktalarını oturum açmadan sunar. Kimlik doğrulaması gerektiren bir uç noktanın `401`/`403` döndürmesi beklenirken, servis yetkisiz isteği doğrudan işlemeye çalışır:

```
OPTIONS /versionFileUpload HTTP/1.1

HTTP/1.1 200 OK
X-Powered-By: Express
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, OPTIONS, PUT, PATCH, DELETE
Access-Control-Allow-Headers: X-Requested-With,content-type
```

Ana sayfa (`GET /`) herhangi bir oturum olmadan tam "Upgrade" arayüzünü döndürür. Yükseltme formu, `.rtm` uzantılı firmware dosyasını doğrudan `/versionFileUpload` uç noktasına gönderir:

```html
<form id="uploadForm" enctype="multipart/form-data"
      action="/versionFileUpload" method="post">
    <input type="file" name="DCT-200-new.rtm" accept=".rtm"/>
</form>
```

İstemci tarafı JavaScript, dosyayı `ajaxSubmit` ile gönderir. İstek hiçbir `Authorization` başlığı veya CSRF jetonu taşımaz; isteğin kaynağının yetkilendirildiğine dair hiçbir kontrol yoktur.

### Kimlik doğrulamasız uç noktalar

| Uç nokta | Yöntem | İşlev |
|---|---|---|
| `/versionFileUpload` | POST (multipart) | Firmware (`.rtm`) dosyasının yüklenmesi |
| `/repairversion` | POST | Kurulu sürümün onarımı |
| `/upgradingactive` | POST | Yükseltme durum sorgusu |

### Aşırı serbest CORS politikası

Servis, tüm yanıtlarında `Access-Control-Allow-Origin: *` başlığını PUT/PATCH/DELETE dahil geniş bir method kümesiyle döndürür. Bu, herhangi bir web sitesinin tarayıcı üzerinden bu uç noktalara istek göndermesine imkân tanır ve kimlik doğrulama eksikliğinin etkisini genişletir.

## Etki

Ağ üzerinden erişebilen, kimliği doğrulanmamış bir saldırgan, hazırladığı bir firmware (`.rtm`) dosyasını `/versionFileUpload` uç noktasına yükleyebilir. Firmware yükseltmesi cihazın çalıştırdığı yazılımı doğrudan değiştirdiğinden, bu işlem cihaz üzerinde uzaktan kod çalıştırma ve tam cihaz ele geçirme, izleme hizmetinin durdurulması veya manipüle edilmesi (ortam alarmlarının bastırılması) ve cihazda kalıcılık sağlanarak iç ağa dayanak noktası oluşturulması ile sonuçlanabilir.

Zafiyet kuruma özgü bir yapılandırma hatası değil, ürünün ortak bileşeninden kaynaklanır. Doğrulama, üretim ortamına risk vermemek amacıyla yalnızca salt-okunur gözlemlerle yapılmış; cihaza herhangi bir dosya yüklenmemiş, yükseltme veya onarım işlemi tetiklenmemiştir.

## İlişkili Zayıflıklar

- CWE-306 — Missing Authentication for Critical Function (birincil)
- CWE-434 — Unrestricted Upload of File with Dangerous Type
- CWE-494 — Download of Code Without Integrity Check
- CWE-942 — Permissive Cross-domain Policy with Untrusted Domains

## Şiddet

Kritik — CVSS 3.1 Temel Puan 9.8 (`AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`)

Saldırganın herhangi bir yetkiye veya kullanıcı etkileşimine ihtiyacı yoktur; saldırı ağ üzerinden, düşük karmaşıklıkla gerçekleştirilebilir. Firmware yüklemesi gizlilik, bütünlük ve kullanılabilirliğin tamamını yüksek seviyede etkiler.

## Etkilenen Sürümler

```
Retmon EMS (DCT-200 Terminal)

Etkilenen : 1.0.0.48
```

Doğrulama 1.0.0.48 üzerinde yapıldı. Zafiyetin bulunduğu firmware yükseltme servisi ürünün ortak bileşenidir; aynı ürün ailesindeki kurulumları etkiler.

## Etkilenen Bileşen

Firmware yükseltme servisi (Node.js/Express, TCP/8080) ve kimlik doğrulamasız `POST /versionFileUpload`, `POST /repairversion`, `POST /upgradingactive` uç noktaları.

## Çözüm

1. Firmware yükseltme servisine (TCP/8080) zorunlu kimlik doğrulaması eklenmeli; yetkisiz isteklere `401`/`403` dönülmelidir.
2. Firmware dosyaları için imzalama ve bütünlük doğrulaması (signed firmware) uygulanmalı; yalnızca üretici tarafından imzalanmış firmware kabul edilmelidir.
3. CORS yapılandırmasındaki `*` kaldırılmalı, izin verilen kaynak ve methodlar daraltılmalıdır.
4. Servis yalnızca yönetim ağı/localhost ile sınırlandırılmalı; gereksizse dışarıya kapatılmalıdır.

## Bulan

Alkım Coşkun — Netlore Security
