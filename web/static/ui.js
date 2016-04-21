(function() {
    'use strict';

    e2ee.UI = {}

    $(window).load(function() {
        if ($(document.body).hasClass('startOnLoad')) {
            e2ee.UI.setup()
            e2ee.UI.start()
        }
    })

    // UI Startup
    e2ee.UI.start = function() {
        $('#e2eePassphrase').focus()
        $('span.dragFileInfo').html(
            $('span.dragFileInfo').data('select')
        )
        chrome.storage.local.get("serverUrl", function(result) {
        	var serverUrl = result["serverUrl"]
        	if (serverUrl !== undefined) {
            	document.getElementById("e2eeServerUrl").value = serverUrl;
            }
        })
    }

    e2ee.UI.open = function(username, session) {
        e2ee.session.cryptonSession = session
        console.log('authorizing....')
        e2ee.session.cryptonSession.load('indexer', function(err, container) {
            console.info('loading indexer')
            if (err) {
                if (window.console && window.console.log) {
                    console.info(err)
                    console.info('indexer container does not exist - this is expected when user logins for the first time')
                }
                e2ee.session.cryptonSession.create('indexer', function(err, newContainer) {
                    e2ee.session.indexContainer = newContainer
                    newContainer.add('fileNames', function() {
                        newContainer.get('fileNames', function(err, fileNames) {
                            fileNames['listOfFiles'] = [] // creator of these files
                            fileNames['sharedFiles'] = [] // files from 'listOfFiles' which are shared
                            fileNames['notMineFiles'] = [] // not creator of these files
                            newContainer.save(function(err) {
                                if (err) {
                                    if (window.console && window.console.log) {
                                        console.error('index container could not be saved')
                                    }
                                } else {
                                    e2ee.UI.preparePanels(username)
                                    e2ee.UI.showFiles()
                                    e2ee.UI.recvMessages()
                                }
                            })
                        })
                    })
                })
            } else {
                e2ee.session.cryptonSession.getMessages(function(err, messages) {
                    if (err) {
                        if (window.console && window.console.log) {
                            console.error('index container could not be saved')
                        }
                        return
                    }
                    container.get('fileNames', function(err, fileNames) {
                        if (err) {
                            if (window.console && window.console.log) {
                                console.info(err)
                                console.info('file names from indexContainer could not be retrieved')
                            }
                        } else {
                            var files = fileNames['notMineFiles']
                            console.log(Object.keys(messages))
                            Object.keys(messages).forEach(function(key) {
                                var message = messages[key]
                                if (message.payload.operation === 'share') {
                                    var hmac = message.payload.hmac
                                    var peerName = message.payload.peerName
                                    var fileName = message.payload.fileName
                                    var access = message.payload.access
                                    files.push({
                                        'fileName': fileName,
                                        'peer': peerName,
                                        'access': access,
                                        'hmac': hmac
                                    })
                                } else {
                                    var fileName = message.payload.fileName
                                    var index = files.indexOf(fileName)
                                    files.splice(index, 1)
                                }
                            })
                            container.save(function(err) {
                                if (err) {
                                    if (window.console && window.console.log) {
                                        console.info(err)
                                    }
                                    // todo: now we let it continue as this error is most likely
                                    // due to nothing changed in the container
                                }
                                e2ee.session.indexContainer = container
                                e2ee.UI.preparePanels(username)
                                e2ee.UI.showFiles()
                                e2ee.UI.recvMessages()

                                e2ee.session.cryptonSession.deleteMessages(function() {})
                            })
                        }
                    })
                })
            }
        })
    }

    e2ee.UI.deleteMessage = function(messageId) {
        e2ee.session.cryptonSession.inbox.delete(messageId, function() {
            alert(messageId + ' deleted')
        })
    }

    e2ee.UI.setup = function() {
        $('div.encryptionContainer').hide()

        $('#forgotPasswordLink').on('click', function() {
            //todo
        })

        e2ee.UI.addSharedFile = function(message, messageId, addToUI) {
            var hmac = message.hmac
            var peerName = message.peerName
            var fileName = message.fileName
            var access = message.access
            if (addToUI) {
                e2ee.UI.addFileElement(fileName, true, false)
            }
            //todo: disable check boxes for access rights

            e2ee.session.indexContainer.get('fileNames', function(err, fileNames) {
                if (err) {
                    if (window.console && window.console.log) {
                        console.info(err)
                        console.info('file names from indexContainer could not be retrieved')
                    }
                } else {
                    var files = fileNames['notMineFiles']
                    files.push({
                        'fileName': fileName,
                        'peer': peerName,
                        'access': access,
                        'hmac': hmac
                    })
                    e2ee.session.indexContainer.save(function(err) {
                        if (err) {
                            if (window.console && window.console.log) {
                                console.error(err)
                            }
                        } else {
                            e2ee.session.cryptonSession.inbox.delete(messageId, function() {
                                console.log('message deleted: ' + messageId)
                                console.log(e2ee.session.cryptonSession.inbox.messages)
                            })
                        }
                    })
                }
            })
        }

        e2ee.UI.removeSharedFile = function(message, messageId, removeFromUI) {
            var fileName = message.fileName
            if (removeFromUI) {
                var fileElement = document.getElementById(fileName).parentElement
                var parent = fileElement.parentElement
                parent.removeChild(fileElement)
            }
            e2ee.session.indexContainer.get('fileNames', function(err, fileNames) {
                if (err) {
                    if (window.console && window.console.log) {
                        console.info(err)
                        console.info('file names from indexContainer could not be retrieved')
                    }
                    return
                }
                var filesList = fileNames['notMineFiles']
                var index = filesList.indexOf(fileName)
                filesList.splice(index, 1)
                e2ee.session.indexContainer.save(function(err) {
                    if (err) {
                        if (window.console && window.console.log) {
                            console.error(err)
                        }
                    } else {
                        e2ee.UI.showInfo(fileName, 'File was successfully unshared.', true)
                        e2ee.session.cryptonSession.inbox.delete(messageId, function() {
                            console.log('message deleted: ' + messageId)
                            console.log(e2ee.session.cryptonSession.inbox.messages)
                        })
                    }
                })
            })
        }

        e2ee.UI.handleMessage = function(message, affectUI) {
            var operation = message.payload.operation
            if (operation === 'share') {
                e2ee.UI.addSharedFile(message.payload, message.messageId, affectUI)
            } else {
                e2ee.UI.removeSharedFile(message.payload, message.messageId, affectUI)
            }
        }

        /* recvMessages is for real time messages, not implemented right now */
        e2ee.UI.recvMessages = function() {
            e2ee.session.cryptonSession.on('message', function(message) {
                // do this messages do not come if you do not logout and login after the registration?
                e2ee.UI.handleMessage(message, true)
            })
        }

        e2ee.UI.getCheckedFiles = function() {
            var cs = $(':checkbox')
            var files = []
            for (var i = 0; i < cs.length; i++) {
                if (cs[i].checked) {
                    var fileName = cs[i].id
                    files.push(fileName)
                }
            }
            return files
        }

        e2ee.UI.uncheck = function(fileName) {
            var cs = $(':checkbox')
            for (var i = 0; i < cs.length; i++) {
                if (cs[i].id === fileName) {
                    cs[i].checked = false
                }
            }
        }

        $('body').on('click', '#sharingTable .close', function(event) {
            var fileName = e2ee.UI.getCheckedFiles()[0]
            var row = event.target.parentElement
            var user = row.getElementsByTagName("td")[0].textContent
            e2ee.session.cryptonSession.getPeer(user, function callback(err, peer) {
                if (err) {
                    if (window.console && window.console.log) {
                        console.error(err)
                    }
                    return
                }
                e2ee.session.cryptonSession.load(fileName, function(err, container) {
                    if (err) {
                        if (window.console && window.console.log) {
                            console.error(err)
                        }
                        return
                    }
                    container.unshare(peer, function(err) {
                        if (err) {
                            if (window.console && window.console.log) {
                                console.error(err)
                            }
                            return
                        }
                        e2ee.session.indexContainer.get('fileNames', function(err, fileNames) {
                            if (err) {
                                if (window.console && window.console.log) {
                                    console.info(err)
                                    console.info('file names from indexContainer could not be retrieved')
                                }
                                return
                            }

                            var sharedFiles = fileNames['sharedFiles']
                            var ind = $(row).index()
                            var fInd = sharedFiles.indexOf(fileName)
                            sharedFiles.splice(fInd, 1)
                            document.getElementById("sharingTable").deleteRow(ind)
                            var cs = $(':checkbox')
                            for (var i = 0; i < cs.length; i++) {
                                if (cs[i].checked) {
                                    var p = cs[i].parentElement
                                    var img = p.children[p.children.length - 1]
                                    $(img).hide()
                                }
                            }
                            e2ee.session.indexContainer.save(function(err) {
                                if (err) {
                                    if (window.console && window.console.log) {
                                        console.error(err)
                                    }
                                    return
                                }
                                var headers = {}
                                var payload = {
                                    operation: 'unshare',
                                    fileName: fileName
                                }
                                peer.sendMessage(headers, payload, function(err, messageId) {
                                    if (err) {
                                        if (window.console && window.console.log) {
                                            console.err(err)
                                        }
                                    }
                                    e2ee.UI.showInfo(fileName, 'File has been successfully unshared.', true)
                                })
                            })
                        })
                    })
                })
            })
        })

        $('body').on('click', '#addUser', function(event) {
            var file = e2ee.UI.getCheckedFiles()[0] // todo for all files
            var user = $("#e2eeUsernameShare").val()

            e2ee.session.indexContainer.get('fileNames', function(err, fileNames) {
                if (err) {
                    if (window.console && window.console.log) {
                        console.info(err)
                        console.info('file names from indexContainer could not be retrieved')
                    }
                    return
                }
                var sharedFiles = fileNames['sharedFiles']
                var alreadyShared = false
                Object.keys(sharedFiles).forEach(function(key) {
                    if (file === sharedFiles[key].fileName && user === sharedFiles[key].user) {
                        alreadyShared = true
                        return
                    }
                })
                if (alreadyShared) {
                    console.log('already shared')
                    e2ee.UI.showInfo(user, err, false)
                    return
                }
                e2ee.session.cryptonSession.getPeer(user, function callback(err, peer) {
                    if (err) {
                        if (window.console && window.console.log) {
                            console.error(err)
                        }
                        return
                    }
                    e2ee.session.cryptonSession.load(file, function(err, container) {
                        if (err) {
                            if (window.console && window.console.log) {
                                console.error(err)
                            }
                            return
                        }
                        container.share(peer, function(err) {
                            if (err) {
                                e2ee.UI.showInfo(user, err, false)
                                if (window.console && window.console.log) {
                                    console.log(err)
                                }
                                return
                            }
                            e2ee.session.indexContainer.get('fileNames', function(err, fileNames) {
                                if (err) {
                                    if (window.console && window.console.log) {
                                        console.info(err)
                                        console.info('file names from indexContainer could not be retrieved')
                                    }
                                } else {
                                    var sharedFiles = fileNames['sharedFiles']
                                    var access = $("input[name='access']:checked").val()
                                    var user = $("#e2eeUsernameShare").val()
                                    e2ee.UI.addUserRow("sharingTable", user, access)
                                    $("#e2eeUsernameShare")[0].value = ""
                                    sharedFiles.push({
                                        'fileName': file,
                                        'access': access,
                                        'user': user
                                    })
                                    e2ee.session.indexContainer.save(function(err) {
                                        if (err) {
                                            if (window.console && window.console.log) {
                                                console.error(err)
                                            }
                                        } else {
                                            var cs = $(':checkbox')
                                            for (var i = 0; i < cs.length; i++) {
                                                if (cs[i].checked) {
                                                    var p = cs[i].parentElement
                                                    var img = p.children[p.children.length - 1]
                                                    $(img).show()
                                                }
                                            }
                                            var headers = {}
                                            var payload = {
                                                hmac: container.nameHmac,
                                                operation: 'share',
                                                fileName: file,
                                                peerName: e2ee.session.cryptonSession.account.username,
                                                access: access
                                            }
                                            peer.sendMessage(headers, payload, function(err, messageId) {
                                                if (err) {
                                                    if (window.console && window.console.log) {
                                                        console.err(err)
                                                    }
                                                }
                                                e2ee.UI.showInfo(file, 'File has been successfully shared to user ' + user + '.', true)
                                            })
                                        }
                                    })
                                }
                            })
                        })
                    })
                })
            })
        })

        $('#share').on('click', function() {
            var files = e2ee.UI.getCheckedFiles()
            if (files.length === 0) {
                //todo: some message
                return false
            }
            var file = files[0]
            e2ee.session.indexContainer.get('fileNames', function(err, fileNames) {
                if (err) {
                    if (window.console && window.console.log) {
                        console.info(err)
                        console.info('file names from indexContainer could not be retrieved')
                    }
                    return
                }
                var sharedFiles = fileNames['sharedFiles']

                bootbox.dialog({
                    title: "Add members",
                    className: "sharedUsers",
                    message: '<form>' +
                        '<input type="radio" name="access" value="read only" checked="checked"> ' +
                        '<span>read only </span> ' +
                        '<input type="radio" name="access" value="modify"><span>modify</span>' +
                        '</form>' +
                        '<div id="adding">' +
                        '<input type="text" class="form-control" id="e2eeUsernameShare" maxlength="128" spellcheck="false" placeholder="Username"/>' +
                        '<input id="addUser" type="submit" name="addUser" value="Add" />' +
                        '</div>' +
                        '<div class="tableHeader">' +
                        '<span class="title">Member</span><span>Permissions</span>' +
                        '</div>' +
                        '<table id="sharingTable" border="1">' +
                        '</table>',
                    buttons: {
                        success: {
                            label: "Done",
                            className: "shareDone"
                        }
                    }
                })
                Object.keys(sharedFiles).forEach(function(key) {
                    if (file === sharedFiles[key].fileName) {
                        e2ee.UI.addUserRow("sharingTable", sharedFiles[key].user, sharedFiles[key].access)
                    }
                })
            })
            return false
        })

        $('body').on('click', '#getPeer', function(event) {
            var user = $("#e2eeUsernameTrusted").val()
            e2ee.session.cryptonSession.getPeer(user, function callback(err, peer) {
                if (err) {
                    console.error(err);
                    return;
                }
                //$("#e2eeUsernameTrusted")[0].value = ""
                var chars = peer.fingerprint.split('')
                var h = ''
                for (var i = 0; i < chars.length; i++) {
                    if (i > 0 & i % 4 == 0) {
                        h += " "
                    }
                    h += chars[i]
                }
                $("#fingerprint")[0].innerHTML = h
            })
        })

        e2ee.UI.addUserRow = function(table, user, someProperty) {
            var table = document.getElementById(table)
            var row = table.insertRow(0)
            var cell1 = row.insertCell(0)
            var cell2 = row.insertCell(1)
            var cell3 = row.insertCell(2)

            cell1.innerHTML = user
            cell1.className = 'user'

            cell2.innerHTML = someProperty
            cell2.className = 'permission'
            cell3.innerHTML = "X"
            cell3.className = 'close'
        }

        $('body').on('click', '#trust', function(event) {
            var user = $("#e2eeUsernameTrusted").val()
            var alreadyTrusted = false
                // peers are already loaded because trustedPeers have been loaded when filling the table
            Object.keys(e2ee.session.cryptonSession.peers).forEach(function(key) {
                var peer = e2ee.session.cryptonSession.peers[key]
                if (key === user && peer.trusted) {
                    alreadyTrusted = true
                    return
                }
            })
            if (alreadyTrusted) {
                e2ee.UI.showInfo(user, 'User already trusted.', false)
                return
            }
            e2ee.session.cryptonSession.getPeer(user, function callback(err, peer) {
                if (err) {
                    if (window.console && window.console.log) {
                        console.info(err)
                    }
                    return
                }
                peer.trust(function(err) {
                    if (err) {
                        if (window.console && window.console.log) {
                            console.info(err)
                        }
                        return
                    }
                    var user = $("#e2eeUsernameTrusted").val()
                    e2ee.UI.addUserRow("trustedTable", user, peer.fingerprint)
                    $("#e2eeUsernameTrusted")[0].value = ""
                    $("#fingerprint")[0].innerHTML = Array(17).join("---- ")
                    e2ee.UI.showInfo(user, 'User is now trusted.', true)
                })
            })
        })

        $('body').on('click', '#trustedTable .close', function(event) {
            var row = event.target.parentElement
            var ind = $(row).index()
            var user = row.getElementsByTagName("td")[0].textContent
            e2ee.session.cryptonSession.getPeer(user, function callback(err, peer) {
                if (err) {
                    if (window.console && window.console.log) {
                        console.error(err)
                    }
                    return
                }
                peer.untrust(function(err) {
                    if (err) {
                        if (window.console && window.console.log) {
                            console.info(err)
                        }
                        return
                    }
                    document.getElementById("trustedTable").deleteRow(ind)
                })
            })
        })

        $('#addTrustedUser').on('click', function() {
            e2ee.session.peersContainer.get("peers", function(err, peers) {
                if (err) {
                    return callback(err)
                }
                //var peers = trustedPeers.value
                bootbox.dialog({
                    title: "Add trusted user",
                    className: "trustedUsers",
                    message: '<div id="adding">' +
                        '<input type="text" class="form-control" id="e2eeUsernameTrusted" maxlength="128" spellcheck="false" placeholder="Username"/>' +
                        '<input id="getPeer" type="submit" name="getPeer" value="Get" />' +
                        '</div>' +
                        '<div id="fingerprintInfo">Fingerprint of user\'s public keys:' +
                        '<br><span id="fingerprint">' +
                        Array(17).join("---- ") +
                        '</span>' +
                        '</div>' +
                        '<input id="trust" type="submit" name="trust" value="Trust" />' +
                        '<div class="tableHeader">' +
                        '<span class="title">Trusted user</span><span>Fingerprint</span>' +
                        '</div>' +
                        '<table id="trustedTable" border="1">' +
                        '</table>',
                    buttons: {
                        success: {
                            label: "Done",
                            className: "shareDone"
                        }
                    }
                })
                Object.keys(peers).forEach(function(key) {
                    e2ee.UI.addUserRow("trustedTable", key, peers[key].fingerprint)
                })
            })
            return false
        })

        $('#download').on('click', function() {
            $('#statusInfo').html('downloading and decrypting...')
            var files = e2ee.UI.getCheckedFiles()
            console.info(files)
            async.each(files, e2ee.crypto.downloadFile, function(err) {})
            return false
        })

        $('#delete').on('click', function() {
            var files = e2ee.UI.getCheckedFiles()
            async.each(files, e2ee.crypto.deleteFile, function(err) {
                if (window.console && window.console.log) {
                    console.info('Downloading finished')
                }
                for (var i = 0; i < files.length; i++) {
                    var fileName = files[i]
                    var fileElement = document.getElementById(fileName).parentElement
                    var parent = fileElement.parentElement
                    parent.removeChild(fileElement)
                }
                var container = e2ee.session.indexContainer
                container.get('fileNames', function(err, fileNames) {
                    if (err) {
                        if (window.console && window.console.log) {
                            console.info(err)
                            console.info('file names from indexContainer could not be retrieved')
                        }
                    } else {
                        var filesList = fileNames['listOfFiles']
                        var l = filesList.length
                        for (var i = 0; i < l; i++) {
                            var fileName = filesList[i]
                            var index = filesList.indexOf(fileName)
                            filesList.splice(index, 1)
                        }
                        container.save(function(err) {
                            if (err) {
                                if (window.console && window.console.log) {
                                    console.error(err)
                                }
                            } else {
                                e2ee.UI.showInfo(fileName, 'Deletion was successful.', true)
                            }
                        })
                    }
                })
            })
            return false
        })

        $('#logout').on('click', function() {
            chrome.runtime.reload();
        })

        $('form.unlockForm').on('submit', function() {
            var passphrase = $('#e2eePassphrase').val()
            var serverUrl = $('#e2eeServerUrl').val()

            if (!passphrase.length) {
                $('#e2eePassphrase').select()
                return false
            }
            if (passphrase.length > 6) {
        		chrome.identity.getAuthToken({ 'interactive': true }, function(token) {
  					crypton.token = token
	        		chrome.identity.getProfileUserInfo(function(userInfo) {
	  					var username = userInfo["email"]
		            	if (serverUrl !== "") {
		                	chrome.storage.local.set({"serverUrl": serverUrl})
		                }
		                crypton.openSession(username, passphrase)
		                $('.notification').html('signing in ...')
					})
				})
            } else {
                $('#e2eePassphrase').select()
                $('.notification').html('Passphrase is not long enough.')
            }
            return false
        })

        e2ee.UI.showFiles = function() {
            $('div.unlock').delay(200).fadeOut(200, function() {
                $('div.selectFile').fadeIn(200)
            })
        }

        e2ee.UI.showInfo = function(objectName, info, positive) {
            var m
            var clName
            if (positive) {
                m = '<span class="sInfo"><img src="static/icons/ok.png" alt="OK" height="20" width="20">' + '<span>' + info + '</span></span>'
                clName = 'ObjectInfoPos'
            } else {
                m = '<span class="sInfoNeg"><span>' + info + '</span></span>'
                clName = 'ObjectInfoNeg'
            }
            $('#encryptionInfo').html('<span class=' + clName + '>' + objectName + '</span>' + m)
        }

        e2ee.UI.preparePanels = function(username) {
            window.URL = window.webkitURL || window.URL
            $("#userInfo button")[0].innerHTML = username + '<span class="caret"></span>'
            var container = e2ee.session.indexContainer
            container.get('fileNames', function(err, fileNames) {
                if (err) {
                    if (window.console && window.console.log) {
                        console.info(err)
                        console.info('file names from indexContainer could not be retrieved')
                    }
                } else {
                    var files = fileNames['listOfFiles'] // file names
                    var sharedFileNames = jQuery.map(fileNames['sharedFiles'], function(b) {
                        return b.fileName
                    })
                    for (var i = 0; i < files.length; i++) {
                        var fileName = files[i]
                        var shared = false
                        if (sharedFileNames.indexOf(fileName) > -1) {
                            shared = true
                        }
						e2ee.crypto.getContainer(fileName, function(fileContainer) { 
            				fileContainer.get('metadata', function(err, metadata) {
                				if (err) {
                    				if (window.console && window.console.log) {
                        				console.info(err)
                        				console.info('file not available: ' + fileName)
                    				}
                				} else {
			                        e2ee.UI.addFileElement(fileName, metadata["date"], shared, true)
                				}
                			})
                		})
                    }
                    files = fileNames['notMineFiles']
                    for (var i = 0; i < files.length; i++) {
                        var file = files[i]
				        e2ee.crypto.getContainerByHmac(file.hmac, file.peer, function(fileContainer) {
							fileContainer.get('metadata', function(err, meta) {
                                if (err) {
                                    if (window.console && window.console.log) {
                                        console.info(err)
                                        console.info('file not available: ' + file.hmac)
                                    }
                                } else {
			                        e2ee.UI.addFileElement(file.fileName, meta["date"], true, false)
                                }
                            })
				        })
                    }

                    $('#back').fadeIn(200)
                    $('body').animate({
                        backgroundColor: '#f5f5f5'
                    })
                }
            })
        }

        e2ee.UI.addFileElement = function(fileName, metadata, shared, isMyContainer) {
            var c = '<input id="' + fileName + '" type="checkbox" name="file" value="">'
            var icon = "share.png"
            var iconSize = 22
            if (!isMyContainer) {
                icon = "shared_from.png"
                iconSize = 26
            }
            var htmlElement = '<div class="fileElement">' + c + '<div class="fileInfo"><p>'
            htmlElement += fileName + '</p><span>' + metadata + '</span></div><img src="static/icons/'
            htmlElement += icon + '" alt="shared" height="' + iconSize + '" width="' + iconSize + '"></div>'

            $('#filesContainer').append(htmlElement)
            if (!shared) {
                var last = $('.fileElement:last-child')
                var image = last.children()[last.children().length - 1]
                $(image).hide()
            }
        }

        e2ee.UI.clearAfterDownloading = function(fileName) {
            e2ee.UI.uncheck(fileName)
            setTimeout(function() {
                $('.progressBarFill').css({
                    'width': '0',
                    'transition': 'none'
                })
                $('#statusInfo').html('')
                e2ee.UI.showInfo(fileName, 'Download was successful.', true)
            }, 1000)
        }

        e2ee.UI.addFile = function(fileName, metadata, alreadyExists) {
            if (!alreadyExists) {
                e2ee.UI.addFileElement(fileName, metadata, false, true)
            }
        }

        $('div.fileSelector').on('dragover', function() {
            $('span.dragFileInfo').html(
                $('span.dragFileInfo').data('drop')
            )
            return false
        })

        $('div.fileSelector').on('dragleave', function() {
            $('span.dragFileInfo').html(
                $('span.dragFileInfo').data('select')
            )
            return false
        })

        $('div.fileSelector').on('drop', function(e) {
            $('span.dragFileInfo').html(
                $('span.dragFileInfo').data('read')
            )
            e.preventDefault()
            var files = e.originalEvent.dataTransfer.files
            var file = files[0]
            e2ee.UI.handleFileSelection(file)
            return false
        })

        $('div.fileSelector').click(function() {
            $('input.fileSelectDialog').click()
        })

        $('input.fileSelectDialog').change(function(e) {
            e.preventDefault()
            if (!this.files) {
                return false
            }
            $('span.dragFileInfo').html(
                $('span.dragFileInfo').data('read')
            )
            var file = this.files[0]
                // Pause to give the operating system a moment to close its
                // file selection dialog box so that the transition to the
                // next screen will be smoother.
            setTimeout(function() {
                e2ee.UI.handleFileSelection(file)
            }, 600)
            return false
        })

        e2ee.UI.handleFileSelection = function(file) {
            e2ee.util.resetCurrentFile()
            e2ee.session.currentFile.fileObject = file

            setTimeout(function() {
                $('span.dragFileInfo').html(
                    $('span.dragFileInfo').data('select')
                )
            }, 1000)
            e2ee.crypto.encryptFile(e2ee.session.currentFile.fileObject,
                e2ee.UI.fileOperationIsComplete)
            $('form.process').trigger('encrypt:start', e2ee.session.currentFile.fileObject.size)
        }

        $('form.process').on('encrypt:start', function(event, fileSize) {
            $('#statusInfo').html('encrypting...')
            e2ee.UI.animateProgressBar(0, fileSize)
        })

        $('form.process').on('encrypt:failed', function(event, errorCode) {
            $('.progressBarFill').css({
                'width': '0',
                'transition': 'none'
            })
        })

        $('form.process').on('submit', function(event) {
            event.preventDefault()
            e2ee.crypto.encryptFile(e2ee.session.currentFile.fileObject,
                e2ee.UI.fileOperationIsComplete)
            $('form.process').trigger('encrypt:start', e2ee.session.currentFile.fileObject.size)
        })

    }

    e2ee.UI.fileOperationIsComplete = function(fileName) {
        $('#statusInfo').html('')
        setTimeout(function() {
            $('.progressBarFill').css({
                'width': '0',
                'transition': 'none'
            })
        }, 1)
    }

    // The crypto worker calls this method when a
    // decrypt or encrypt operation has failed.
    // Operation argument is either 'encrypt' or 'decrypt'.
    e2ee.UI.fileOperationHasFailed = function(operation, errorCode) {
        $('form.process').trigger(operation + ':failed', errorCode)
    }

    // Convert an integer from bytes into a readable file size.
    // For example, 7493 becomes '7KB'.
    e2ee.UI.readableFileSize = function(bytes) {
        var KB = bytes / 1024
        var MB = KB / 1024
        var GB = MB / 1024
        if (KB < 1024) {
            return Math.ceil(KB) + 'KB'
        } else if (MB < 1024) {
            return (Math.round(MB * 10) / 10) + 'MB'
        } else {
            return (Math.round(GB * 10) / 10) + 'GB'
        }
    }

    // Animate progress bar based on currentProgress and total.
    e2ee.UI.animateProgressBar = function(currentProgress, total) {
        var percentage = total ? currentProgress / total * 100 : 0
            // If percentage overflows 100 due to chunkSize greater
            // than the size of the file itself, set it to 100
        percentage = percentage > 100 ? 100 : percentage
        $('.progressBarFill').css({
            'transition': 'none'
        })
        $('.progressBarFill').css({
            'width': percentage + '%',
            'transition': 'width 1ms linear'
        })

        setTimeout(function() {
            $('.progressBarFill').css({
                'width': percentage + '%',
                'transition': 'width 1ms linear'
            })
        }, 1)
    }
})()