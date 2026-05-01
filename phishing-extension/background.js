const API_URL = 'https://phising-project-api-1.onrender.com'  // ✅ correct URL + /predict

const SKIP_SCHEMES = ['chrome://', 'chrome-extension://', 'about:', 'devtools://']

chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
    const { url, tabId, frameId } = details

    if (frameId !== 0) return
    if (SKIP_SCHEMES.some(s => url.startsWith(s))) return

    try {
        const res = await fetch(API_URL, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url })
        })

        const data = await res.json()

        if (data.phishing) {
            // ✅ storage.local instead of storage.session
            chrome.storage.local.set({
                blockedUrl: url,
                riskScore: data.score,
                risk: data.risk
            }, () => {
                chrome.tabs.update(tabId, {
                    url: chrome.runtime.getURL('warning.html')
                })
            })
        }

    } catch (err) {
        console.error('Phishing API error:', err)
    }
})