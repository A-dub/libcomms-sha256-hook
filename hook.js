'use strict';
/*
 * libComms.dll SHA-256 / CIP auth capture
 * Target: 32-bit libComms.dll, Ghidra image base 0xDA000000
 * Use with: frida-inject -n <emulator.exe> -s hook.js  > capture.txt 2>&1
 */

var MODNAME = 'libEmulateComms5580.dll';   // if not found, the script prints candidates below

// RVAs = Ghidra address - 0xDA000000
var OFF = {
  SHA256_Update: 0x87c0,  // da0087c0(ctx, data, len)  cdecl stack args
  SHA256_Final:  0x8b20,  // da008b20 -> marks a hash-block boundary
  validate:      0x42650  // da042650 cip_auth_validate_challenge (ctx in EAX)
};

function dumpBytes(p, len) {
  try { return hexdump(p, { length: len, ansi: false, header: false }); }
  catch (e) { return '  <unreadable ' + p + ' len ' + len + '>'; }
}

function install(mod) {
  console.log('[+] ' + mod.name + ' base=' + mod.base);

  // Every chunk fed into SHA-256 update. Concatenate the UPDATE dumps between
  // two FINAL markers = the exact preimage of one hash.
  Interceptor.attach(mod.base.add(OFF.SHA256_Update), {
    onEnter: function (args) {
      var ptr_ = args[1];          // data pointer  ([esp+8])
      var len  = args[2].toInt32();// length        ([esp+0xc])
      console.log('UPDATE len=' + len);
      if (len > 0 && len < 0x10000) console.log(dumpBytes(ptr_, len));
    }
  });

  Interceptor.attach(mod.base.add(OFF.SHA256_Final), {
    onLeave: function () { console.log('--- FINAL ---'); }
  });

  // Marker + direct key read. Context pointer is in EAX per the decompiler;
  // we also try ECX in case the convention differs. key ptr @ +0x1c, len @ +0x88.
  Interceptor.attach(mod.base.add(OFF.validate), {
    onEnter: function () {
      console.log('==================== cip_auth_validate_challenge ====================');
      var regs = [['eax', this.context.eax], ['ecx', this.context.ecx]];
      for (var i = 0; i < regs.length; i++) {
        var name = regs[i][0], c = regs[i][1];
        try {
          var kp = c.add(0x1c).readPointer();
          var kl = c.add(0x88).readU32();
          console.log('  via ' + name + ': key_ptr=' + kp + '  key_len=' + kl);
          if (kl > 0 && kl < 512) console.log(dumpBytes(kp, kl));
        } catch (e) { /* wrong reg, ignore */ }
      }
    }
  });
}

var m = Process.findModuleByName(MODNAME);
if (m) {
  install(m);
} else {
  console.log('[..] ' + MODNAME + ' not loaded yet; waiting...');
  var tries = 0;
  var iv = setInterval(function () {
    var mm = Process.findModuleByName(MODNAME);
    if (mm) { clearInterval(iv); install(mm); return; }
    if (++tries === 25) {   // ~5s: help diagnose a name mismatch
      console.log('[!] Still not found. Loaded modules matching /comm/i:');
      Process.enumerateModules().forEach(function (x) {
        if (/comm/i.test(x.name)) console.log('    ' + x.name + '  ' + x.base);
      });
      console.log('[!] If the real name differs, edit MODNAME at the top of hook.js and re-run.');
    }
  }, 200);
}
