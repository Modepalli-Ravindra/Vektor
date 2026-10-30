import React from 'react';

export default function VektorLogo({ className = "w-9 h-9" }) {
  return (
    <div className={`${className} rounded-xl bg-[#141010] border border-[#8B1111]/70 flex items-center justify-center p-0.5 shadow-[3px_3px_8px_#040404,inset_1px_1px_1px_rgba(255,255,255,0.15)] shrink-0 overflow-hidden select-none`}>
      <img
        src="/logo.png"
        alt="Vektor Emblem"
        className="w-full h-full object-contain filter drop-shadow-[0_0_4px_rgba(255,46,46,0.3)]"
      />
    </div>
  );
}
