import React, { useState, useEffect } from 'react';

const ConsentBanner = ({ onConsent }: { onConsent: () => void }) => {
  const [consentGiven, setConsentGiven] = useState(false);

  useEffect(() => {
    const stored = localStorage.getItem('consent_accepted');
    if (stored === 'true') setConsentGiven(true);
  }, []);

  const acceptConsent = () => {
    localStorage.setItem('consent_accepted', 'true');
    setConsentGiven(true);
    onConsent();
  };

  if (consentGiven) return null;

  return (
    <div className="fixed bottom-0 w-full bg-gray-800 text-white p-4 shadow-lg z-50">
      <div className="max-w-4xl mx-auto flex justify-between items-center">
        <p className="text-sm">
          We use cookies and require your consent before connecting to your wallet or signing messages. See our <a href="/terms" className="underline">Terms of Use</a>.
        </p>
        <button onClick={acceptConsent} className="bg-green-500 px-4 py-2 rounded ml-4">
          Accept & Continue
        </button>
      </div>
    </div>
  );
};

export default ConsentBanner;
