chrome.storage.session.get(['blockedUrl', 'riskScore', 'risk'], (data) => {
    document.getElementById('blocked-url').textContent = data.blockedUrl || 'Unknown URL'
    document.getElementById('risk-score').textContent =
        data.riskScore ? `${(data.riskScore * 100).toFixed(1)}%` : '—'
})

function proceedAnyway() {
    chrome.storage.session.get(['blockedUrl'], (data) => {
        if (data.blockedUrl) {
            window.location.href = data.blockedUrl
        }
    })
}