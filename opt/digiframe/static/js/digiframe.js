
function showToast(message, message_class){
    let objToast = $('#main-toast');
    objToast.removeClass('bg-success');
    objToast.removeClass('bg-danger');
    objToast.removeClass('bg-warning');
    objToast.addClass(message_class);
    $('#main-toast-text').text(message);
    objToast.toast('show');
}

function callRemote(url, data, dataType, callbackFunction){
    let contentType = dataType === 'json' ? 'application/json;' : '';
    return $.ajax({
        type: "POST",
        contentType: contentType + "charset=utf-8",
        url: url,
        data: data,
        success: function (resp) {
            if (resp) {
                let message_class;
                if (resp.result === 200) {
                    message_class = 'bg-success';
                } else {
                    message_class = 'bg-danger';
                }
                showToast(resp.data.message, message_class);

                if (callbackFunction !== undefined) {
                    callbackFunction(resp.result, resp.data);
                }
            }
        },
        error: function (req, status, error) {
            showToast(error + ' [' + req.status + ']', 'bg-danger');
            console.error('error during callRemote(): ', url, data, req, status, error);
        },
        dataType: dataType
    });
}

function userEdit(row_class){
    let editElementList = [].slice.call(document.querySelectorAll('.' + row_class))
    editElementList.forEach(function (element){
        element.disabled = !element.disabled;
    });
}

function removeUser(result, json_data){
    if (result === 200) {
        let uid = json_data.uid;
        $('tr.user_' + uid).remove();
    }
}

function userDelete(uid){
    if (uid.match(/^NEW:\d/)) {
        let n_uid = uid.replaceAll("NEW:", '');
        $('tr.new_' + n_uid).remove();
    } else {
        callRemote('/users', JSON.stringify({func: 'delete', uid: uid}), 'json', removeUser);
    }
}

function userAdd(row_class){
    let template = $('tr.clone_master')[0];
    let max_id = template.dataset.userMaxId;
    let new_user = template.innerHTML;
    let new_id = "new_" + max_id;
    // replace placeholder
    new_user = new_user.replaceAll("clone_", new_id + "_");
    new_user = new_user.replaceAll("${max_id}", max_id);
    // create new row from template
    let tr = document.createElement('tr');
    tr.innerHTML = new_user
    $(tr).attr('class', new_id);
    $('tr.' + row_class)[0].parentNode.append(tr);

    // add Caps Lock detector
    $('#' + new_id + '_password').keyup(detectCapsLock);

    // scroll to new element
    $('html, body').animate(
        {scrollTop: ($('tr.' + new_id).offset().top)},
        'fast'
    );

    // update validation rules
    let user_name = $('#' + new_id + '_name');
    if (user_name) {
        user_name.attr('minlength', 1);
        user_name.attr('required', 'required');
        user_name.focus();
    }
    template.dataset.userMaxId = (parseInt(template.dataset.userMaxId) + 1).toString();
}

function detectCapsLock(event) {
    // If "caps lock" is pressed, display the warning text
    let capsLockOn;
    if (event.originalEvent) {
        capsLockOn = event.originalEvent.getModifierState("CapsLock");
    } else {
        capsLockOn = event.getModifierState("CapsLock");
    }
    if (capsLockOn === true) {
        showToast('Caps Lock is active', 'bg-warning');
    }
}