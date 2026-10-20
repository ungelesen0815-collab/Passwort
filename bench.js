global.window = {
    btoa: function(str) { return Buffer.from(str, 'binary').toString('base64'); },
    atob: function(b64) { return Buffer.from(b64, 'base64').toString('binary'); }
};

const VaultCrypto = require('./vault.js').VaultCrypto;

function optimizedBufferToBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0, len = bytes.byteLength; i < len; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return window.btoa(binary);
}

function runBenchmark() {
    console.log('Running benchmark...');
    const buffer = new ArrayBuffer(1024 * 1024 * 5); // 5MB

    const startBaseline = process.hrtime.bigint();
    VaultCrypto.bufferToBase64(buffer);
    const endBaseline = process.hrtime.bigint();
    const baselineTime = Number(endBaseline - startBaseline) / 1000000;
    console.log('Baseline bufferToBase64:', baselineTime, 'ms');

    const startOptimized = process.hrtime.bigint();
    optimizedBufferToBase64(buffer);
    const endOptimized = process.hrtime.bigint();
    const optimizedTime = Number(endOptimized - startOptimized) / 1000000;
    console.log('Optimized bufferToBase64:', optimizedTime, 'ms');

    const improvement = ((baselineTime - optimizedTime) / baselineTime) * 100;
    console.log(`Improvement: ${improvement.toFixed(2)}%`);
}

runBenchmark();
