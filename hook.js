// TP-Link router web interface hooks for encrypt and decrypt functions

(function () {
    var attempt = 0;
    var encryptCount = 0;
    var decryptCount = 0;

    function setup() {
        if (typeof $ === 'undefined' || !$.encrypt || !$.encrypt.AES) {
            if (attempt++ < 50) return setTimeout(setup, 100);
            return console.error("failed to find encryption");
        }

        var origEncrypt = $.encrypt.AES.prototype.encrypt;
        $.encrypt.AES.prototype.encrypt = function (plain) {
            encryptCount++;
            console.log("ENCRYPTED:", plain);
            try {
                var json = JSON.parse(plain);
                console.log("JSON:", JSON.stringify(json, null, 2));
            } catch (e) { }
            var cipher = origEncrypt.call(this, plain);
            return cipher;
        };

        var origDecrypt = $.encrypt.AES.prototype.decrypt;
        $.encrypt.AES.prototype.decrypt = function (cipher) {
            var plain = origDecrypt.call(this, cipher);
            decryptCount++;
            console.log("DECRYPTED:", plain);
            try {
                var json = JSON.parse(plain);
                console.log("JSON:", JSON.stringify(json, null, 2));

                var checkObj = function (obj, path) {
                    if (!obj || typeof obj !== 'object') return;
                    for (var key in obj) {
                        var val = obj[key];
                        var fullPath = path ? path + '.' + key : key;
                        if (/(pwd|password|passwd)/i.test(key) && val && typeof val === 'string' && val.length > 0) {
                            console.log("PASSWORD:", fullPath + ":", val);
                        }
                        if (typeof val === 'object') checkObj(val, fullPath);
                    }
                };
                checkObj(json, '');
            } catch (e) { }
            return plain;
        };
        setTimeout(enableHiddenFeatures, 1000);
    }

    function enableHiddenFeatures() {
        window.INCLUDE_OPTION66 = 1; // enable backup/restore access
        window.INCLUDE_RESTORE_ADMIN_PASSWORD = 1;
        window.INCLUDE_RESTORE_USER_PASSWORD = 1;
        window.INCLUDE_USER_RESTRICTION = 0;
        window.INCLUDE_WRITE_ADMIN_PWD = 1;
        if (typeof $ !== 'undefined') {
            $.userType = "Admin";
            $.unlocked = 1;
        }

        // show all sidebar menu items
        if ($ && $('#menu').length > 0) {
            $('#menu').find('a').each(function (i) {
                var $a = $(this);
                var $li = $a.parent('li');
                var text = $a.text().trim();
                var url = $a.attr('url') || $a.attr('href') || '';
                var isHidden = $li.css('display') === 'none' || $li.hasClass('nd');
                console.log((i + 1) + ".", {
                    text: text,
                    url: url,
                    hidden: isHidden,
                    classes: $li.attr('class')
                });
            });
        }
    }

    setup();
})();
