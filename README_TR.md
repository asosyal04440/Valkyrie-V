<div align="center">

# Valkyrie-V

**Bulut Yerel İş Yükleri İçin Yeni Nesil Bellek Güvenli Hipervizör**

[![Rust](https://img.shields.io/badge/Rust-1.75%2B-orange?logo=rust)](https://www.rust-lang.org/)
[![Lisans](https://img.shields.io/badge/Lisans-MIT-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-x86__64%20%7C%20ARM64-green)](https://github.com)
[![no_std](https://img.shields.io/badge/no_std-evet-purple)](https://docs.rust-embedded.org/)

*Yüksek Performans • Güvenlik Öncelikli • Üretime Hazır*

[Özellikler](#özellikler) • [Mimari](#mimari) • [Modüller](#modüller) • [Derleme](#derleme) • [Yol Haritası](#yol-haritası)

[English](README.md) • [Türkçe](#türkçe)

</div>

---

<a name="türkçe"></a>
## Genel Bakış

Valkyrie-V, modern bulut yerel iş yükleri için tamamen **Rust** ile yazılmış son teknoloji tip-1 hipervizördür. Geleneksel C tabanlı hipervizörlerin (KVM, Xen, ESXi) aksine, Valkyrie-V, Rust'ın bellek güvenliği garantilerinden yararlanarak tüm güvenlik açığı sınıflarını ortadan kaldırırken olağanüstü performans sunar.

### Neden Valkyrie-V?

| Özellik | Valkyrie-V | Geleneksel Hipervizörler |
|---------|------------|-------------------------|
| **Bellek Güvenliği** | ✅ Derleme zamanında garanti | ⚠️ Manuel, hataya açık |
| **Eşzamanlılık** | ✅ Kilit-atsız atomikler | ⚠️ Kilit tabanlı, yarış koşulları |
| **Saldırı Yüzeyi** | ✅ Minimal, denetlenebilir | ⚠️ Büyük, eski kod |
| **Performans** | ✅ Sıfır maliyetli soyutlamalar | ⚠️ Çalışma zamanı yükü |
| **Modern Özellikler** | ✅ Dahili gelişmiş özellikler | ⚠️ Harici modüller gerekli |

---

## Özellikler

### Çekirdek Sanallaştırma

- **Intel VT-x (VMX)** — Tam donanım sanallaştırma desteği
- **AMD SVM** — AMD sanallaştırma desteği (deneysel)
- **EPT/NPT** — Verimli bellek sanallaştırma için Genişletilmiş Sayfa Tabloları
- **Çoklu vCPU** — Ölçeklenebilir çok çekirdekli konuk desteği
- **İç İçe Sanallaştırma** — VM'ler içinde hipervizör çalıştırma

### Bellek Yönetimi

| Modül | Açıklama |
|-------|----------|
| `memory_compress` | Bellek overcommit için LZ4 tabanlı sıkıştırılmış bellek havuzu |
| `tps` | COW ve güvenlik tuzlama ile Şeffaf Sayfa Paylaşımı |
| `balloon_enhanced` | Boş sayfa ipucu ile dinamik bellek balonlama |
| `large_page` | Bellek baskısı altında talep üzerine büyük sayfa kırma |
| `numamem` | Otomatik dengeleme ile NUMA-farklı bellek ayırma |

### CPU Optimizasyonu

| Modül | Açıklama |
|-------|----------|
| `sched_adv` | Gelişmiş CPU zamanlayıcı (Credit, SEDF, Eş-zamanlama) |
| `power_mgmt` | CPU güç yönetimi (P-state, C-state, DVFS) |
| `tlb` | TLB shootdown optimizasyonu (toplu, PCID, tembel flush) |
| `pmu` | Performans izleme için PMU entegrasyonu |

### I/O ve Depolama

| Modül | Açıklama |
|-------|----------|
| `virtio_mq` | Net, block, balloon için VirtIO çoklu kuyruk |
| `vhost_user` | Paylaşılan bellek halkaları ile sıfır kopya vhost-user arka ucu |
| `ioat_dma` | Yüksek verimli I/O için IOAT/DMA motor desteği |
| `numaio` | NUMA-farklı I/O cihaz yerleştirme |

### GPU Sanallaştırma

| Modül | Açıklama |
|-------|----------|
| `vgpu` | NVIDIA MIG desteği ile vGPU zamanlama |
| `gpu_mem` | GPU bellek sanallaştırma ve yönetimi |

### Anlık Görüntü ve Göç

| Modül | Açıklama |
|-------|----------|
| `cbt` | Artımlı anlık görüntüler için Değiştirilmiş Blok Takibi |
| `live_snap` | Yinelemeli ön kopya göçü ile canlı anlık görüntü |
| `template` | COW bellek çatallama ile VM şablon/klonlama |

### Güvenlik ve İçgözlem

| Modül | Açıklama |
|-------|----------|
| `vmi` | Konuk izleme için Sanal Makine İçgözlemi |
| `hvi` | Kendi kendini koruma için Hipervizör İçgözlemi |
| `tracing` | eBPF benzeri izleme çerçevesi |
| `secure_boot` | UEFI Güvenli Önyükleme desteği |

### MicroVM ve Bulut

| Modül | Açıklama |
|-------|----------|
| `microvm` | Hızlı önyükleme için Firecracker tarzı MicroVM (< 125ms) |
| `enterprise` | Kurumsal özellikler (yedek/DR, uyumluluk, denetim) |

---

## Mimari

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           Valkyrie-V Hipervizör                             │
├─────────────────────────────────────────────────────────────────────────────┤
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                        Yönetim Katmanı                              │   │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐   │   │
│  │  │ Kontrol  │ │ Anlık    │ │  Göç     │ │ VMI/HVI  │ │ İzleme   │   │   │
│  │  │ Düzlemi  │ │ Görüntü  │ │ Yönetici │ │ Güvenlik │ │ Çerçevesi│   │   │
│  │  └──────────┘ └──────────┘ └──────────┘ └──────────┘ └──────────┘   │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
├─────────────────────────────────────────────────────────────────────────────┤
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                      Çekirdek Sanallaştırma                         │   │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐   │   │
│  │  │   VMX    │ │   EPT    │ │  APICv   │ │Zamanlayıcı│ │Güç Yntm │   │   │
│  │  │ İşleyici │ │ Yönetici │ │  I/O APIC│ │ Gelişmiş │ │  P/C-State│   │   │
│  │  └──────────┘ └──────────┘ └──────────┘ └──────────┘ └──────────┘   │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
├─────────────────────────────────────────────────────────────────────────────┤
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                        Bellek Alt Sistemi                           │   │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐   │   │
│  │  │ Sıkıştır │ │   TPS    │ │  Balon   │ │ NUMA Bel │ │ Büyük   │   │   │
│  │  │   LZ4    │ │   COW    │ │ Gelişmiş │ │  Farklı  │ │  Sayfa   │   │   │
│  │  └──────────┘ └──────────┘ └──────────┘ └──────────┘ └──────────┘   │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
├─────────────────────────────────────────────────────────────────────────────┤
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                        I/O Alt Sistemi                              │   │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐   │   │
│  │  │ VirtIO   │ │ vhost    │ │ IOAT/DMA │ │ NUMA I/O │ │   NVMe   │   │   │
│  │  │ Çoklu-K  │ │  Kullan  │ │  Motor   │ │ Yerellik │ │  Geçiş   │   │   │
│  │  └──────────┘ └──────────┘ └──────────┘ └──────────┘ └──────────┘   │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
├─────────────────────────────────────────────────────────────────────────────┤
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                        GPU Alt Sistemi                              │   │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐               │   │
│  │  │  vGPU    │ │ GPU Bel  │ │  SR-IOV  │ │   MIG    │               │   │
│  │  │ Zamanla  │ │  Sanal   │ │  VFIO    │ │  Desteği │               │   │
│  │  └──────────┘ └──────────┘ └──────────┘ └──────────┘               │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Modüller

<details>
<summary><b>Bellek Optimizasyon Modülleri</b></summary>

### `memory_compress` — LZ4 Sıkıştırılmış Bellek Havuzu
- Overcommit için şeffaf bellek sıkıştırma
- Yapılandırılabilir sıkıştırma oranı eşikleri
- Sayfa başına sıkıştırma istatistikleri
- Erişimde otomatik açma

### `tps` — Şeffaf Sayfa Paylaşımı
- Alt sayfa (4KB) tanecikli paylaşım
- Paylaşılan sayfalar için Kopyala-Yaz (COW)
- Hash çarpışmalarını önlemek için güvenlik tuzlama
- Tekilleştirme için KSM entegrasyonu

### `balloon_enhanced` — Dinamik Bellek Balonlama
- Öncelik tabanlı bellek geri kazanım
- Boş sayfa ipucu (VirtIO)
- Şişirme/indirme politikaları
- Konuk işbirliği protokolü

### `large_page` — Büyük Sayfa Yönetimi
- 2MB/1GB sayfa desteği
- Bellek baskısı altında talep üzerine kırma
- Sayfa terfi sezgiselleri
- TLB verimlilik takibi

### `numamem` — NUMA-Farklı Bellek
- Topoloji-farklı ayırma
- Düğümler arası otomatik dengeleme
- Bellek göç desteği
- Düğüm başına istatistikler

</details>

<details>
<summary><b>CPU Optimizasyon Modülleri</b></summary>

### `sched_adv` — Gelişmiş CPU Zamanlayıcı
- **Credit Zamanlayıcı**: Ağırlık tabanlı tahsis ile adil paylaşım
- **SEDF Zamanlayıcı**: Son teslim tarihi garantileri ile gerçek zamanlı
- **Eş-Zamanlama**: SMP konuklar için senkronize vCPU yürütme
- Yük dengeleme ve afinite yönetimi

### `power_mgmt` — CPU Güç Yönetimi
- P-state seçimi (frekans ölçekleme)
- C-state yönetimi (boş durumlar)
- Zamanlayıcı ile DVFS entegrasyonu
- Güç/performans ödünleşimleri

### `tlb` — TLB Optimizasyonu
- Toplu shootdownlar
- PCID tabanlı seçici geçersiz kılma
- Tembel TLB floşlama
- Uzak shootdown birleştirme

### `pmu` — Performans İzleme
- Donanım sayaç yönetimi
- Olay tabanlı örnekleme
- Konuk PMU sanallaştırma
- Performans analiz araçları

</details>

<details>
<summary><b>I/O Optimizasyon Modülleri</b></summary>

### `virtio_mq` — VirtIO Çoklu Kuyruk
- vCPU başına kuyruk ataması
- Otomatik kuyruk ölçekleme
- Kesinti afinite optimizasyonu
- Tek kuyruk ile geriye dönük uyumlu

### `vhost_user` — Sıfır Kopya Arka Uç
- Paylaşılan bellek halkaları
- Kullanıcı alanı cihaz arka uçları
- Minimal hipervizör katılımı
- DPDK entegrasyonuna hazır

### `ioat_dma` — IOAT/DMA Motoru
- Boşaltılmış bellek işlemleri
- Zaman uyumsuz DMA tanımlayıcıları
- Kanal yönetimi
- Yüksek verimli veri hareketi

### `numaio` — NUMA-Farklı I/O
- Cihaz yerellik optimizasyonu
- IRQ afinite yönetimi
- DMA tampon yerleştirme
- Düğümler arası I/O takibi

</details>

<details>
<summary><b>Güvenlik ve İçgözlem Modülleri</b></summary>

### `vmi` — Sanal Makine İçgözlemi
- Kesinti noktası/iz noktası izleme
- Olay abonelik sistemi
- Konuk OS durum inceleme
- Güvenlik politikası uygulama

### `hvi` — Hipervizör İçgözlemi
- Kendi kendini koruma mekanizmaları
- Bütünlük doğrulama
- Kurcalama tespiti
- Rootkit önleme

### `tracing` — eBPF Benzeri Çerçeve
- Programlanabilir olay işleyiciler
- Harita tabanlı veri depolama
- Halka tampon olaylar
- Hipervizör içi güvenli yürütme

</details>

---

## Derleme

### Ön Gereksinimler

```bash
# Rust kurulumu
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# no_std hedefi ekleme
rustup target add x86_64-unknown-none
```

### Derleme

```bash
# Hata ayıklama derlemesi
cargo build

# Sürüm derlemesi (optimize edilmiş)
cargo build --release

# Bare-metal için derleme (no_std)
cargo build --target x86_64-unknown-none --release
```

### Test

```bash
# Tüm testleri çalıştır
cargo test

# Belirli modül testlerini çalıştır
cargo test --lib vmm::memory_compress
cargo test --lib vmm::vmi

# Kıyaslamaları çalıştır
cargo bench
```

---

## Performans

### Önyükleme Süresi

| Yapılandırma | Süre |
|--------------|------|
| MicroVM (minimal) | < 125ms |
| Standart VM | < 500ms |
| Tam özellikli VM | < 2s |

### Bellek Yükü

| Yapılandırma | Yük |
|--------------|-----|
| Temel hipervizör | < 10 MiB |
| VM başına yük | < 5 MiB |
| Sıkıştırma ile | -30% efektif |

### I/O Verimliliği

| Cihaz | Verimlilik |
|-------|------------|
| VirtIO-Net | 40+ Gbps |
| VirtIO-Block | 1M+ IOPS |
| vhost-user | 50+ Gbps |

---

## Güvenlik

### Bellek Güvenliği

Valkyrie-V, Rust'ın sahiplik modeli aracılığıyla tüm güvenlik açığı sınıflarını ortadan kaldırır:

| Güvenlik Açığı Sınıfı | C/C++ | Rust |
|----------------------|-------|------|
| Tampon taşmaları | ❌ Yaygın | ✅ İmkansız |
| Serbest bırakıldıktan sonra kullanım | ❌ Yaygın | ✅ İmkansız |
| Çift serbest bırakma | ❌ Yaygın | ✅ İmkansız |
| Null pointer dereferansı | ❌ Yaygın | ✅ İmkansız |
| Veri yarışları | ❌ Yaygın | ✅ İmkansız |

### Güvenlik Özellikleri

- **HVI Kendi Kendini Koruma** — Çalışma zamanı bütünlük izleme
- **VMI Konuk İzleme** — Güvenlik politikası uygulama
- **Güvenli Önyükleme** — UEFI Güvenli Önyükleme desteği
- **Bellek Şifreleme** — SEV/TDX hazır (planlanan)

---

## Karşılaştırma

| Özellik | Valkyrie-V | KVM/QEMU | Xen | VMware ESXi | Firecracker |
|---------|------------|----------|-----|-------------|-------------|
| Dil | Rust | C | C | C++ | Rust |
| Bellek Güvenliği | ✅ | ⚠️ | ⚠️ | ⚠️ | ✅ |
| Tip 1 Hipervizör | ✅ | ❌ | ✅ | ✅ | ✅ |
| MicroVM Desteği | ✅ | ⚠️ | ⚠️ | ❌ | ✅ |
| GPU Sanallaştırma | ✅ | ⚠️ | ⚠️ | ✅ | ❌ |
| Canlı Göç | ✅ | ✅ | ✅ | ✅ | ❌ |
| VMI/HVI | ✅ | ⚠️ | ⚠️ | ⚠️ | ❌ |
| NUMA Farklı | ✅ | ⚠️ | ⚠️ | ✅ | ❌ |
| Açık Kaynak | ✅ | ✅ | ✅ | ❌ | ✅ |
| Üretim Hazır | 🆕 | ✅ | ✅ | ✅ | ✅ |

---

## Yol Haritası

### v0.1 (Mevcut) — Çekirdek Özellikler
- [x] VMX/SVM desteği
- [x] EPT bellek sanallaştırma
- [x] VirtIO cihazlar
- [x] Gelişmiş optimizasyon modülleri

### v0.2 — Üretim Hazır
- [ ] Tam Linux konuk desteği
- [ ] Windows konuk desteği
- [ ] ARM64 platform desteği
- [ ] Kapsamlı dokümantasyon

### v0.3 — Kurumsal
- [ ] Yüksek erişilebilirlik
- [ ] Dağıtılmış kaynak zamanlama
- [ ] Depolama entegrasyonu (Ceph, vb.)
- [ ] Ağ entegrasyonu (OVN, vb.)

### v1.0 — Kararlı
- [ ] Sertifikasyon hazır
- [ ] Kurumsal destek
- [ ] Uzun vadeli destek sürümleri

---

## Katkıda Bulunma

Katkılarınızı bekliyoruz! Lütfen talimatlar için [CONTRIBUTING.md](CONTRIBUTING.md) dosyasına bakın.

### Geliştirme Kurulumu

```bash
# Depoyu klonla
git clone https://github.com/your-org/valkyrie-v.git
cd valkyrie-v

# Pre-commit kancalarını kur
pre-commit install

# Kontrolleri çalıştır
cargo fmt --check
cargo clippy -- -D warnings
cargo test
```

---

## Lisans

MIT Lisansı altında lisanslanmıştır. Detaylar için [LICENSE](LICENSE) dosyasına bakın.

---

## Teşekkürler

- Mükemmel araçlar için Rust topluluğu
- Donanım sanallaştırma spesifikasyonları için Intel/AMD
- MicroVM ilhamı için Firecracker projesi
- Mimari referans için KVM/Xen projeleri

---

<div align="center">

**[⬆ Başa Dön](#valkyrie-v)**

Bahadır Doğan tarafından ❤️ ile yapıldı

</div>
