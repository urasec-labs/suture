---
title: "Kaynak Kodu Olmayan Bir Binary'ye Enstrümantasyon Dikmek"
subtitle: "SUTURE'un kapalı kaynak x86-64 ELF'lere tam kenar kapsama nasıl kazandırdığı — ve bunun maliyeti"
tags: [güvenlik, binary-analiz, fuzzing, rust, x86-64, elf]
lang: tr
---

# Kaynak Kodu Olmayan Bir Binary'ye Enstrümantasyon Dikmek

*SUTURE üzerine çalışma notu: strip edilmiş bir x86-64 ELF'e kaynak kod,
derleyici ve runtime shim olmadan tam kenar kapsama eklemek — gerçek bir
1.1 MB binary üzerinde ortaya çıkan üç hatayla ve hâlâ çözülmemiş 3.25×
dosya büyümesiyle birlikte.*

---

## Boşluk

Coverage-guided fuzzer'lar geri bildirimi hedefi **yeniden derleyerek** alır.
`afl-clang`, `afl-llvm`, libFuzzer'ın `-fsanitize=fuzzer`'ı — hepsi kaynak
kod, derleyici ve hâlâ çalışan bir build istiyor.

Bu, üç büyük hedef sınıfını dışarıda bırakıyor:

| Sınıf | Örnek | Engeli |
|---|---|---|
| Kapalı kaynak binary'ler | dağıtımdaki `libxml2.so.2`, proprietary `.so`, `.node` eklentileri | kaynak yok |
| Eski build'ler | 2017 build'ini yeniden üretmek | yanlış toolchain, eksik bağımlılık |
| Enstrümantasyona dirençli build'ler | `#pragma optimize`, inline asm, ağır LTO | yeniden derlemek sadık olmaz |

Mevcut binary-only alternatiflerin her biri farklı bir bedel ödüyor. **AFL++
QEMU mode** her blok için x86'yı IR'ye geri kaldırıyor. **DrDynamic /
DynamoRIO / Intel PT** dinamik binary enstrümantasyonu — yürütme başına
büyüklüklerine maliyet. Ve var olan statik rewriter'lar (`objcopy`, radare2
scriptleri, Ghidra scriptleri) kodu yamalar ama **çalıştırılabilir, geri
bildirim alınabilir** bir binary üretmez.

SUTURE'un hedefi: bir ELF ve başka hiçbir şey almak, ve davranışı aynı
olan, kapsamayı statik bilinen bir adresten bildiren, runtime iş birliği
gerektirmeyen yeni bir ELF üretmek.

---

## Fikir

AFL coverage map'ini şöyle indeksler:

```c
bitmap[(prev_loc >> 1) ^ (cur_loc >> 1)]     // 16 KiB
```

`prev_loc` **TLS**'te taşınır. Bu tek hamlede iki sorun satın alır:

1. Her basic-block girişinde bir TLS yüklemesi.
2. **Kayıplı (lossy) hash** — farklı kenarlar aynı slot'a çakışıyor.

SUTURE ikisini de kaldırıyor: her kenara **rewrite anında statik bir tamsayı
ID** atıyor. ID kod üretilirken bilindiği için enstrümantasyon şuna iniyor:

```asm
taken_stub:
    inc byte [rip + disp32]   ; → table[edge_id], displacement çevrimdışı sabit
    jmp  rel32                ; → orijinal successor
```

Hash yok, TLS yok, runtime relocation geçişi yok, shim `.so` yok.

### Neden harita yazılabilir bir segmentte olmamalı

İlk tasarım bütün stub'ları *ve* coverage tablosunu tek bir `R|W` `PT_LOAD`
segmentine koyuyordu. Bu yanlış ve sonradan bakınca apaçık: bir stub
**çalıştırılmalı**, tablo **yazılmalı** ve NX zorunlu olan her sistemde tek bir
yazılabilir segment, stub çalışır çalışmaz fault verir. Tek bir çalıştırılabilir
segment ise counter increment'inde fault verir.

Çözüm iki segment — stub'lar için `R|X`, tablo için `R|W` — ve bu ilk bakışta
bütün şemayı bozuyor gibi görünüyor, çünkü stub'lar tabloyu adresliyor.
Bozmuyor, ve sebebi tam olarak söylenmeye değer:

> RIP-relative adresleme, işaretli 32-bit **göreli** bir displacement'tır. İki
> vaddr de rewrite anında sabitleniyor ve hiçbiri diğerinden bağımsız
> rastgeleleştirilmiyor; yani çevrimdışı hesaplanan displacement her yükleme
> adresinde doğru kalıyor. PIE binary'ler kendiliğinden çalışıyor.

Gerekçe ayakta kaldı; sadece segment sayısına dair sonuç yanlıştı.

---

## Zor kısım: `jcc rel8` sığmıyor

x86-64'ün değişken uzunluklu talimat kodlaması tüm zorluğun tamamı.

| | bayt |
|---|---|
| `je rel8` | **2** |
| `je rel32` | **6** |
| `jmp rel32` — yazmak istediğimiz | **5** |

2 baytlık `je rel8` yerine 5 baytlık jump yazılamaz. Generic "binary patcher"ların
geri bildirim alınabilir binary üretememesinin sebebi tam olarak bu.

SUTURE'un cevabı **hibrit patch + fırsatçı basic-block relocation**:

```
orijinal blok  --jmp rel32-->  arena kopyası  --jmp rel32-->  dispatch stub
```

İlk sıçrama bloğun **girişine** yazılıyor, terminatörün üstüne değil: dalden
önceki baytler bloğun kendi gövdesi ve onları terk edebiliriz, çünkü kopya
arena'da duruyor. Bu bloğun en az 5 bayt olmasını gerektiriyor — 2 baytlık ve
boş gövdeli durum tam olarak bununla ilgili.

Relocation bir `memcpy` değil. Her talimat yeniden **kodlanmak** zorunda,
çünkü RIP-relative operand, `[rip+d]`'nin *orijinal* blokta doğru yeri
göstermesini sağlayan displacement'i taşır; ham bayt kopyası yeni konumda yanlış
adresi hesaplar. Bu gereksinim SUTURE'un `iced-x86` kullanmasının tamamı —
kütüphane bir decoder değil, **encoder** de sunuyor.

Giriş jump'ı için bile kısa olan bloklar, *önceki bloğun stub'ı* üzerinden
yönlendirilir; o zaten yönlendirildiği için 5 baytlık jump'ın kısa blokun
içine sığması gerekmez.

---

## Bu işin yapmaya değer olup olmadığına karar veren ölçüm

Exact-edge iddiası, AFL'in 16 KiB map'inin gerçek control flow'da gerçekten
çakışmıyorsa hiçbir şey ifade etmez. Bu empirik bir soru, yani ölçüldü.

`suture analyze` sweep'i ve hash'i binary'nin gerçek edge kümesi üzerinde
çalıştırıyor — execution yok, Linux yok, baytların saf fonksiyonu. busybox
1.35.0 (static, musl, 1.1 MB) üzerinde:

| | |
|---|---|
| benzersiz edge | 128,236 |
| dokundukları AFL++ 16 KiB slot | 16,384'ün 13,643'ü |
| **AFL++ çakışma oranı** | **%89.4** |
| SUTURE'in ihtiyaç duyduğu slot | 65,536 (AFL'in sabit 16 KiB'inin 4×'ı) |

**AFL++, gerçek control flow'da benzersiz edge'lerin %89.4'ünü birbirine
karıştırıyor.** Tez marjinal değil; ve map'in boşalmak yerine doymuş olması,
sonucun güçlü hali.

### Adlandırılmaya değer metodolojik tuzak

Bu ölçümü yazmanın apaçık yolu:

```rust
let edges: Vec<(u32, u32)> = (0..50_000).map(|i| (i, i + 1)).collect();
```

Bu fixture **yanlış** ve ilk yazılan da buydu. Zincirleme `(i, i+1)` kenarları
için AFL'in indeksi `i ^ (i+1)`'e düşüyor, ve `i ^ (i+1)` her zaman `2^k − 1`
biçiminde. Yani 50.000 benzersiz edge yaklaşık **17 slot**a çöküyor, 16 KiB'e
değil.

Zincirleme fixture çakışma oranını *abartırdı* — ama mesele şu: sayı tamamen
edge dağılımına bağlı ve makul görünen bir fixture yanlış fonksiyonu ölçüyor.
Gerçek üreteç sabit bir LCG ve zincirleme davranış, neden başlık sayısı
olmadığını açıklayan yorumuyla kendi regresyon testi olarak korunuyor.

---

## Yalnızca gerçek bir binary'nin bulabileceği üç hata

Elle yazılmış 58 baytlık fixture'lara karşı bütün testler geçiyordu. Bunların
üçü de busybox'tan geçene kadar görünmezdi.

### 1. Sweep, 1.1 MB'lık binary'den 3 blok görüyordu

`sweep`, blok liderlerini bulmak için `decode_run` çağırıyordu, o da ilk kontrol
transferinde duruyor. Yani sadece ilk daldan önceki birkaç talimatı görüyordu.
busybox: **3 blok, %0 çakışma oranı.**

En kötü tarafı yanlış olması değil — tezi **yanlış gerekçeyle doğrulanmış
gibi göstermesi**. %0 çakışma oranı exact edge'leri "doğrulamış" olurdu, oysa
hiçbir şey ölçülmemişti.

Çözüm resync'li doğrusal tarama: segmentin tamamını yürümek ve geçersiz bir
bayta denk gelince üstünden atlayıp devam etmek, çünkü gerçek `.text` kodu jump
tabloları ve string literal'larıyla iç içe geçiyor.

### 2. Her `call`'da blok bölmek her şeyi şişiriyordu

`call` kontrol aktarır ama *geri döner*. Coverage açısından sonraki talimat
fallthrough ile gelir ve AFL call'u edge saymaz. Orada bölmek, coverage map'inin
ayırt edemeyeceği edge'ler için gereğinden çok düğümlü bir grafik üretti: 100k
blok ve %41.6 relocation.

Çözüm, kodun karıştırdığı iki şeyi ayırmak: `is_control_transfer` (decode
run'ın bittiği yer) ile `splits_block` (coverage bloğunun başladığı yer). İkisi
uyuşmalı ve uyuşmuyordu.

### 3. Dolaylı jump'ların **sıfır** edge'i vardı

`build_edges` *mnemonic'e* göre dallanıyordu: koşulsuz bir dalın doğrudan
olduğu varsayılıyordu. `jmp rax` koşulsuz ama statik hedefi yok, yani hiçbir
şey eklemeyen bir kola düşüyordu. Dolaylı jump ile biten her bloğun **hiç edge'i
yoktu** ve sonra planner tarafından atlanıyordu.

O bloklar coverage map'inde sessizce yoktu. Hata yok, uyarı yok — sadece eksik
coverage, ancak bir blok sayımı assert'i toplam tutmayınca fark edildi.

Artık geçerli olan invariant: **hiçbir bloğun edge'i sıfır olamaz.**

Bu üçünün her biri, düzeltmeyi değil *hatayı* adlandıran regresyon testine sahip.

---

## Bedeli, dürüstçe

| | busybox 1.35.0 |
|---|---|
| relocation oranı | %51.6 |
| enstrümanlanmayan dolaylı dallar | blokların %40.9'u |
| çıktı büyümesi | **3.25×** (1.1 MB → 3.7 MB) |
| enstrümantasyon süresi | 15.6 s |

**Projenin kullanıma değerli olup olmadığını belirleyen kısım bu.** 3.25×
büyüyen bir binary teorik bir sıkıntı değil; 3.25× disk, 3.25× page-cache
basıncı ve — arena ikinci bir mapping olduğu için — 3.25× yükleme süresi
demek. Fikir doğru ve uygulama şu an pahalı, ve bu cümlenin iki yarısı aynı
nefeste söylenmeli.

Roadmap'ın ilk maddesi bu yüzden fork server değil, çıktıyı ucuzlatmak:

- **Her blok için 19 baytlık dispatch stub üretmeyi bırak.** Stub neredeyse
  hiç paylaşılmıyor, çünkü kimliği hedef adresini içeriyor ve her blok
  farklı. Relocate edilen blokta increment'ler satır içine yazılabilir; busybox
  üzerinde 2.5 MB arena'nın ~600 KB'sı kazanılır.
- **Blok değil, fonksiyon bazında relocate et.** Fonksiyona `call rel32` ile
  girilir — her zaman 5 bayt. `call`'i yönlendirmek, kısa `jcc`'yi yönlendirmek
  yerine, N relocated bloğu tek relocated fonksiyona indirger.

---

## Henüz çalışmayan şey

Gizleyen bir rewriter'ın, çalışmayandan daha kötü olmasının sebebi bu yüzden
açıkça söyleniyor.

**Coverage map'i geri okunamıyor.** Bitmiş bir sürecin belleği gittiği için
haritayı okumak ya fork server (hedef eşlemeyi yürütmeler boyunca canlı tutar)
ya da hedefin yazdığı paylaşımlı anonim eşleme gerektiriyor.

`suture-exec` uydurma map yerine **boş** map döndürüyor. `suture-fuzz` her koşuyu
`plain-spawn` olarak etiketliyor ve exec/s sayılarının süreç oluşturmayı, fuzzer'ı
değil ölçtüğünü uyarıyor. **Mevcut sürücüden exec/s raporlama.**

Ayrıca henüz yapılmayanlar: `ptrace` trace-equivalence doğrulaması, dolaylı
dal enstrümantasyonu ve AFL++ benchmark'ı.

---

## Doğrulama isteğe bağlı değil

Herhangi bir binary rewriter'a yöneltilebilen en güçlü itiraz şudur: *"çıktının
girdiyle yaptığını yaptığını nasıl biliyorsunuz?"* Bunu bir iddiaya değil,
çalıştırılabilir bir argümana hak ediyor.

`suture verify`, **değişen her `.text` baytının enstrümanın raporladığı patch
aralıklarının içinde olduğunu** denetliyor. Execution gerektirmediği için her
host'ta çalışıyor ve en önemli hata sınıfını yakalıyor: bir bayt kaymış patch.
Bu, hâlâ yüklenen, loader'ın hizalama kongrüansını geçen ve sessizce canlı bir
talimat kaybetmiş bir dosya üretir.

Test paketi bilerek her raporlanan aralığın dışında bir bayt bozuyor ve
denetimin bunu fark ettiğini doğruluyor.

İlgili bir hata: `orig_len` başta `u8` idi, yani 255 bayttan uzun bir blok
raporlanan aralıktan *kısa* kalan bir aralık üretiyordu — ve denetim tam olarak
bu aralıklara güvendiği için kırpılmış bir aralık, bozulmayı yakalamak için
konulmuş kontrolde yanlış "temiz" demek.

---

## Windows'ta Visual Studio olmadan derlemek

İlginç kısım değil ama bir gün gitti ve cevapı apaçık değil.

rustup'un `windows-gnu` toolchain'i `dlltool` ile geliyor ama onun çağırdığı
assembler'ı (`as.exe`) getirmiyor; bu yüzden `dlltool` `CreateProcess` hatası
yazıp geçerli bir import library'yi yazdıktan *sonra* sıfırdan farklı bir exit
koduyla dönüyor. rustc bu exit kodunu ölümcül sayıyor ve build, bu projeyle
ilgisi olmayan `windows-sys`'te ölüyor.

Çözüm onun da üstünde: `clap`'in `color` ve `tracing-subscriber`'ın `ansi`
özelliklerini kapatmak. `windows-sys`'i hiç içeri sokan onlar, ve SUTURE'un
çıktısı zaten satır bazlı ve renksiz. Artı boşluk içermeyen bir linker yolu,
çünkü `rustc` `-C linker=`'ı boşlukta bölüyor ve `C:\Users\...` içindeki bir
boşluk `multiple input filenames provided` üretiyor.

Çekirdek dört crate bilinçli olarak platform-bağımsız; yani zorluğun tamamı olan
rewriter Windows'ta geliştirilip test ediliyor. Fuzzing sürücüsü değil, ve
öyle olduğunu iddia etmiyor.

---

## Nereye gidiyor

1. Çıktıyı ucuzlat (büyüme ≤ 1.3×).
2. Fork server — her gerçek benchmark'ı kapıyor.
3. Dolaylı dallar — blokların %40.9'u en büyük coverage açığı.
4. AFL++ benchmark: `afl-clang-fast` tavan, **kazanılacak olan QEMU mode**, ve
   iki sayı da raporlanıyor.
5. Ancak ondan sonra: yayın.

Sıralamanın neden özelliklerin en eğlenceli göründüğü sıra olmadığına dair
tam gerekçe [`docs/ROADMAP.md`](../docs/ROADMAP.md) dosyasında.

Kaynak: [github.com/urasec-labs/suture](https://github.com/urasec-labs/suture)

---

*Rewriter'ı kıran bir binary bulursan gerçekten duymak isterim — bu yazıdaki
her hata, testlerden daha büyük bir binary denemekle bulundu, ve sıradaki muhtemelen
şimdiden diskinde bir yerde.*
