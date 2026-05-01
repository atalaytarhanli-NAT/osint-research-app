---
name: social-trace
description: Sherlock benzeri kullanıcı adı taraması — verilen username için 20+ büyük platformda kamuya açık profil var mı kontrol eder. Hiçbir oturum/şifre kullanmaz, yalnızca HTTP HEAD/GET ile public profil URL'lerini sorgular.
---

# social-trace

Bir kullanıcı adının popüler platformlarda var olup olmadığını test eder.

## Etik

- **Sadece kamuya açık profil sayfaları** sorgulanır
- Şifre denemesi, brute force, oturum açma yok
- Profilin var olması "o kişiye ait" anlamına gelmez — eş isim çakışması olabilir, açıkça belirt

## Platform listesi (varsayılan)

github, x/twitter, instagram, reddit, medium, dev.to, gitlab, hackernews, youtube,
tiktok, linkedin, pinterest, vimeo, dribbble, behance, soundcloud, twitch, keybase,
hashnode, stackoverflow

## Akış

1. Kullanıcı adı geçerli mi kontrol et (regex `^[A-Za-z0-9_.-]{2,40}$`).
2. Her platform için aşağıdaki URL şablonlarına `WebFetch` at:

```
github       https://github.com/{u}
twitter      https://x.com/{u}
instagram    https://www.instagram.com/{u}/
reddit       https://www.reddit.com/user/{u}/about.json
medium       https://medium.com/@{u}
gitlab       https://gitlab.com/{u}
hackernews   https://news.ycombinator.com/user?id={u}
youtube      https://www.youtube.com/@{u}
tiktok       https://www.tiktok.com/@{u}
linkedin     https://www.linkedin.com/in/{u}
pinterest    https://www.pinterest.com/{u}/
vimeo        https://vimeo.com/{u}
dribbble     https://dribbble.com/{u}
behance      https://www.behance.net/{u}
soundcloud   https://soundcloud.com/{u}
twitch       https://www.twitch.tv/{u}
keybase      https://keybase.io/{u}
hashnode     https://hashnode.com/@{u}
dev_to       https://dev.to/{u}
```

3. Yanıt 200 ve sayfada `Not Found` / `doesn't exist` / `Couldn't find` gibi false-positive marker yoksa profil **var olabilir** demektir.

4. Çıktı:

```json
[
  {
    "platform": "github",
    "url": "https://github.com/{u}",
    "exists": true,
    "confidence": 0.55,
    "note": "Profile candidate — manuel doğrulama önerilir"
  }
]
```

## Notlar

- Aynı kullanıcı adı farklı kişilere ait olabilir (ör. `john` çok yaygın).
- LinkedIn ve Twitter sıkı bot tespiti yapar — yanıt geri gelmezse "indeterminate" işaretle.
- Sonuç tablosuna eş isim riskini her zaman ekle.
