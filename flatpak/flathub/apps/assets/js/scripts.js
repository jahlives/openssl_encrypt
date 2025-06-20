/ Flatpak installation handler
  function installFlatpak(appId) {
      // Try the flatpak: protocol first
      window.location.href = 'flatpak:' + appId;

      // Fallback: show manual installation instructions
      setTimeout(function() {
          alert('If the automatic installation didn\'t work, run this command:\n\nflatpak install custom-repo ' + appId);
      }, 1000);
  }

  // Additional utility functions can go here
