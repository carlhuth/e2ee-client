chrome.app.runtime.onLaunched.addListener(function() {
  chrome.app.window.create('web/index.html', {
    bounds: {
      width: 1200,
      height: 678
    }, 
    resizable: false
  });
});
