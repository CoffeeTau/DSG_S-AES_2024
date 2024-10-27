// ------------------------------------单次加密 --------------------------
function singleEncryption() {  
    const key = document.getElementById("key1").value;
    const plaintext = document.getElementById("plaintext").value;
    const selectedValue = document.querySelector('input[name="n1"]:checked').value;

    // 检查密钥是否为 16 位 01 序列
    if (key.length !== 16) {
        alert("请注意密钥为16位");
        return;
    }
    if (!/^([01])+$/.test(key)) {
        alert("请输入bit格式的密钥");
        return;
    }

    // 检查明文格式是否符合选定的格式
    if (selectedValue === 'bit' && !/^([01])+$/.test(plaintext)) {
        alert("请输入bit格式的明文");
        return;
    }

    // 加密过程
    alert("单次加密中");

    // 发送请求到后端
    fetch('/singleEncrypt', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: `n1=${selectedValue}&plaintext=${plaintext}&key=${key}`
    })
    .then(response => {
        if (!response.ok) {
            throw new Error('Network response was not ok');
        }
        return response.json();
    })
    .then(data => {
        document.getElementById("ciphertextLabel").textContent = data.result;
    })
    .catch(error => console.error('Error:', error));
}



// ------------------------------------双重加密 --------------------------
function doubleEncryption() {
    const key1 = document.getElementById("key1").value;
    const key2 = document.getElementById("key2").value;
    const plaintext = document.getElementById("plaintext").value;
    const selectedValue = document.querySelector('input[name="n1"]:checked').value;

    // 检查密钥是否为 16 位 01 序列
    if (key1.length !== 16 || key2.length !== 16) {
        alert("请注意密钥为16位");
        return;
    }
    if (!/^([01])+$/.test(key1) || !/^([01])+$/.test(key2)) {  // 修改为 ||
        alert("请输入bit格式的密钥");
        return;
    }

    // 检查明文格式是否符合选定的格式
    if (selectedValue === 'bit' && !/^([01])+$/.test(plaintext)) {
        alert("请输入bit格式的明文");
        return;
    }

    // 加密过程
    alert("双重加密中");

    // 发送请求到后端
    fetch('/doubleEncrypt', { 
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: `n1=${selectedValue}&plaintext=${plaintext}&key1=${key1}&key2=${key2}`
    })
    .then(response => {
        if (!response.ok) {
            throw new Error('Network response was not ok');
        }
        return response.json();
    })
    .then(data => {
        document.getElementById("ciphertextLabel").textContent = data.result;
    })
    .catch(error => console.error('Error:', error));
}



// ------------------------------------三重加密 --------------------------
  function tripleEncryption(){


    //先判断用户输入了几个密钥！！！！！！！！！！！！！！！1

    const key1 = document.getElementById("key1").value;
    const key2 = document.getElementById("key2").value;
    const key3 = document.getElementById("key3").value;

    const plaintext = document.getElementById("plaintext").value;
    const selectedValue = document.querySelector('input[name="n1"]:checked').value;
    alert("三重")
    if (key3.length ===0){
        tripleEncryption_two(selectedValue, plaintext, key1, key2);
    }
    else{
        tripleEncryption_three(selectedValue, plaintext, key1, key2, key3);
    }

  }


function tripleEncryption_two(selectedValue, plaintext, key1, key2){

    // 检查密钥是否为 16 位 01 序列
    if (key1.length !== 16 || key2.length !== 16) {
        alert("请注意密钥为16位");
        return;
    }

    if (!/^([01])+$/.test(key1) || !/^([01])+$/.test(key2)) {  // 修改为 ||
        alert("请输入bit格式的密钥");
        return;
    }

    // 检查明文格式是否符合选定的格式
    if (selectedValue === 'bit' && !/^([01])+$/.test(plaintext)) {
        alert("请输入bit格式的明文");
        return;
    }

    // 加密过程
    alert("三重加密中");

    // 发送请求到后端
    fetch('/tripleEncrypt_two', { 
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: `n1=${selectedValue}&plaintext=${plaintext}&key1=${key1}&key2=${key2}`
    })
    .then(response => {
        if (!response.ok) {
            throw new Error('Network response was not ok');
        }
        return response.json();
    })
    .then(data => {
        document.getElementById("ciphertextLabel").textContent = data.result;
    })
    .catch(error => console.error('Error:', error));
}



  function tripleEncryption_three(selectedValue, plaintext, key1, key2, key3){

    // 检查密钥是否为 16 位 01 序列
    if (key1.length !== 16 || key2.length !== 16 || key3.length !== 16) {
        alert("请注意密钥为16位");
        return;
    }
    if (!/^([01])+$/.test(key1) || !/^([01])+$/.test(key2) || !/^([01])+$/.test(key3)) {  // 修改为 ||
        alert("请输入bit格式的密钥");
        return;
    }

    // 检查明文格式是否符合选定的格式
    if (selectedValue === 'bit' && !/^([01])+$/.test(plaintext)) {
        alert("请输入bit格式的明文");
        return;
    }

    // 加密过程
    alert("三重加密中");

    // 发送请求到后端
    fetch('/tripleEncrypt_three', { 
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: `n1=${selectedValue}&plaintext=${plaintext}&key1=${key1}&key2=${key2}&key3=${key3}`
    })
    .then(response => {
        if (!response.ok) {
            throw new Error('Network response was not ok');
        }
        return response.json();
    })
    .then(data => {
        document.getElementById("ciphertextLabel").textContent = data.result;
    })
    .catch(error => console.error('Error:', error));
  }


//   function cbcEncryption(){

//   }



//解密函数

//加密函数
// ------------------------------------单次解密 --------------------------
function singleDecryption() {  
    const key = document.getElementById("key1").value;
    const cyphertext = document.getElementById("plaintext").value;
    const selectedValue = document.querySelector('input[name="n1"]:checked').value;

    // 检查密钥是否为 16 位 01 序列
    if (key.length !== 16) {
        alert("请注意密钥为16位");
        return;
    }
    if (!/^([01])+$/.test(key)) {
        alert("请输入bit格式的密钥");
        return;
    }

    // 检查明文格式是否符合选定的格式
    if (selectedValue === 'bit' && !/^([01])+$/.test(cyphertext)) {
        alert("请输入bit格式的明文");
        return;
    }

    // 加密过程
    alert("单次解密中");

    // 发送请求到后端
    fetch('/singleDecrypt', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: `n1=${selectedValue}&cyphertext=${cyphertext}&key=${key}`
    })
    .then(response => {
        if (!response.ok) {
            throw new Error('Network response was not ok');
        }
        return response.json();
    })
    .then(data => {
        document.getElementById("decryptedPlaintextLabel").textContent = data.result;
    })
    .catch(error => console.error('Error:', error));
}

// ------------------------------------双重解密 --------------------------
function doubleDecryption(){

    const key1 = document.getElementById("key1").value;
    const key2 = document.getElementById("key2").value;

    const cyphertext = document.getElementById("plaintext").value;
    const selectedValue = document.querySelector('input[name="n1"]:checked').value;

    // 检查密钥是否为 16 位 01 序列
    if (key1.length !== 16 || key2.length !== 16) {
        alert("请注意密钥为16位");
        return;
    }
    if (!/^([01])+$/.test(key1) && !/^([01])+$/.test(key2)) {
        alert("请输入bit格式的密钥");
        return;
    }

    // 检查明文格式是否符合选定的格式
    if (selectedValue === 'bit' && !/^([01])+$/.test(cyphertext)) {
        alert("请输入bit格式的明文");
        return;
    }

    // 加密过程
    alert("双重解密中");

    // 发送请求到后端
    fetch('/doubleDecrypt', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: `n1=${selectedValue}&cyphertext=${cyphertext}&key1=${key1}&key2=${key2}`
    })
    .then(response => {
        if (!response.ok) {
            throw new Error('Network response was not ok');
        }
        return response.json();
    })
    .then(data => {
        document.getElementById("decryptedPlaintextLabel").textContent = data.result;
    })
    .catch(error => console.error('Error:', error));
  }

// ------------------------------------三重解密 --------------------------
function tripleDecryption(){


    //先判断用户输入了几个密钥！！！！！！！！！！！！！！！1

    const key1 = document.getElementById("key1").value;
    const key2 = document.getElementById("key2").value;
    const key3 = document.getElementById("key3").value;

    const plaintext = document.getElementById("plaintext").value;
    const selectedValue = document.querySelector('input[name="n1"]:checked').value;
    alert("三重")
    if (key3.length ===0){
        tripleDecryption_two(selectedValue, plaintext, key1, key2);
    }
    else{
        tripleDecryption_three(selectedValue, plaintext, key1, key2, key3);
    }

  }


function tripleDecryption_two(selectedValue, plaintext, key1, key2){

    // 检查密钥是否为 16 位 01 序列
    if (key1.length !== 16 || key2.length !== 16) {
        alert("请注意密钥为16位");
        return;
    }

    if (!/^([01])+$/.test(key1) || !/^([01])+$/.test(key2)) {  // 修改为 ||
        alert("请输入bit格式的密钥");
        return;
    }

    // 检查明文格式是否符合选定的格式
    if (selectedValue === 'bit' && !/^([01])+$/.test(plaintext)) {
        alert("请输入bit格式的明文");
        return;
    }

    // 加密过程
    alert("三重加密中");

    // 发送请求到后端
    fetch('/tripleDecrypt_two', { 
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: `n1=${selectedValue}&plaintext=${plaintext}&key1=${key1}&key2=${key2}`
    })
    .then(response => {
        if (!response.ok) {
            throw new Error('Network response was not ok');
        }
        return response.json();
    })
    .then(data => {
        document.getElementById("decryptedPlaintextLabel").textContent = data.result;
    })
    .catch(error => console.error('Error:', error));
}



  function tripleDecryption_three(selectedValue, plaintext, key1, key2, key3){

    // 检查密钥是否为 16 位 01 序列
    if (key1.length !== 16 || key2.length !== 16 || key3.length !== 16) {
        alert("请注意密钥为16位");
        return;
    }
    if (!/^([01])+$/.test(key1) || !/^([01])+$/.test(key2) || !/^([01])+$/.test(key3)) {  // 修改为 ||
        alert("请输入bit格式的密钥");
        return;
    }

    // 检查明文格式是否符合选定的格式
    if (selectedValue === 'bit' && !/^([01])+$/.test(plaintext)) {
        alert("请输入bit格式的明文");
        return;
    }

    // 加密过程
    alert("三重加密中");

    // 发送请求到后端
    fetch('/tripleDecrypt_three', { 
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: `n1=${selectedValue}&plaintext=${plaintext}&key1=${key1}&key2=${key2}&key3=${key3}`
    })
    .then(response => {
        if (!response.ok) {
            throw new Error('Network response was not ok');
        }
        return response.json();
    })
    .then(data => {
        document.getElementById("decryptedPlaintextLabel").textContent = data.result;
    })
    .catch(error => console.error('Error:', error));
  }


//   function cbcEncryption(){

//   }


function mybruteForce() {
    // 你的处理代码

    const message_plain = document.getElementById("message_plain").value;
    const message_cipher = document.getElementById("message_cipher").value;

    const messageLength_plain = message_plain.length;
    const messageLength_cipher = message_cipher.length;

    // 检查输入是否为空
    if (!messageLength_plain || !messageLength_cipher) {
        alert("请输入明文/密文");
        return;
    }
    if (messageLength_cipher != 16 || messageLength_plain != 16) {
        alert("请注意密/明文为16位"); // 弹出提示框
        return;
    }

    alert("已确认提交");

    // 重置全局变量
    fetch('/reset_variable', {
        method: 'GET'
    })
    .then(response => {
        if (!response.ok) {
            throw new Error('Network response was not ok');
        }
        return response.json();
    })
    .then(data => {
        console.log(data.message); // 输出重置结果信息

        // 启动定时器
        const globalVariableInterval = setInterval(getGlobalVariable, 1000);

        // 提交破解请求
        fetch('/bruteForce', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: `message_plain=${message_plain}&message_cipher=${message_cipher}`
        })
        .then(response => {
            if (!response.ok) {
                throw new Error('Network response was not ok');
            }
            return response.json();
        })
        .then(data => {
            document.getElementById("result_time").textContent = data.time + "s";

            let key1 = data.key1;
            let key2 = data.key2;

            let s = `密钥1：${key1} 密钥2：${key2}`;
            document.getElementById("result_key").innerHTML = s;

            // 破解完成后停止定时器
            clearInterval(globalVariableInterval);
        })
        .catch(error => {
            console.error('Error:', error);
        });
    })
    .catch(error => {
        console.error('Error resetting global variable:', error);
    });
}

function getGlobalVariable() {
    fetch('/get_global_variable')
        .then(response => {
            if (!response.ok) {
                throw new Error('Network response was not ok');
            }
            return response.json();
        })
        .then(data => {
            console.log('Current global variable:', data.global_variable);
            const displayElement = document.getElementById("globalVariableDisplay");

            // 获取当前显示的值（转换为数字），用于平滑过渡
            const currentDisplayValue = parseInt(displayElement.textContent.replace(/\D/g, '')) || 0;
            const newGlobalVariable = data.global_variable;

            // 平滑过渡到新值
            animateValue(currentDisplayValue, newGlobalVariable, 1000, displayElement); // 500ms 为过渡时间
        })
        .catch(error => console.error('Error:', error));
}



// 数字平滑变动函数
function animateValue(start, end, duration, displayElement) {
    let startTime = null;

    function animationStep(timestamp) {
        if (!startTime) startTime = timestamp;
        const progress = timestamp - startTime;
        const currentValue = Math.floor(start + (end - start) * (progress / duration));

        // 使用 span 标签包裹数字部分
        displayElement.innerHTML = `正在经历第 <span class="large-number">${currentValue}</span> 次循环`;

        if (progress < duration) {
            requestAnimationFrame(animationStep);
        } else {
            displayElement.innerHTML = `正在经历第 <span class="large-number">${end}</span> 次循环`; // 确保最后显示精确的终值
        }
    }

    requestAnimationFrame(animationStep);
}



// CBC加密 --------------------------------------------------------------------------

function cbcEncryption() {
    // 获取输入的 IV、密钥1、明文
    const iv = document.getElementById("ivInput").value;
    const key1 = document.getElementById("key1").value;
    const plaintext = document.getElementById("plaintext").value;

    // 获取用户选择的输出格式
    const selectedFormat = document.querySelector('input[name="n1"]:checked');

    // 检查是否选择了格式
    if (!selectedFormat) {
        alert("请选择输出格式（bit 或 ASCII）");
        return;
    }

    const format = selectedFormat.value;

    // 检查输入是否为空
    if (!iv || !key1 || !plaintext) {
        alert("请填写完整的 IV、密钥1 和明文");
        return;
    }

    // 发送 POST 请求到后端
    fetch('/cbc_encrypt', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({
            iv: iv,
            key1: key1,
            plaintext: plaintext,
            format: format  // 将输出格式发送给后端
        })
    })
    .then(response => {
        if (!response.ok) {
            throw new Error('Network response was not ok');
        }
        return response.json();
    })
    .then(data => {
        if (data.error) {
            alert(data.error);
        } else {
            console.log('CBC加密结果:', data.result);
            // 显示加密结果在指定的标签中
            document.getElementById("ciphertextLabel").textContent = `密文: ${data.result}`;
        }
    })
    .catch(error => {
        console.error('Error:', error);
    });
}


// CBC解密 --------------------------------------------------------------------------
function cbcDecryption() {
    // 获取输入的 IV、密钥1、明文
    const iv = document.getElementById("ivInput").value;
    const key1 = document.getElementById("key1").value;
    const plaintext = document.getElementById("plaintext").value;

    // 获取用户选择的输出格式
    const selectedFormat = document.querySelector('input[name="n1"]:checked');

    // 检查是否选择了格式
    if (!selectedFormat) {
        alert("请选择输出格式（bit 或 ASCII）");
        return;
    }

    const format = selectedFormat.value;

    // 检查输入是否为空
    if (!iv || !key1 || !plaintext) {
        alert("请填写完整的 IV、密钥1 和明文");
        return;
    }

    // 发送 POST 请求到后端
    fetch('/cbc_decrypt', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({
            iv: iv,
            key1: key1,
            plaintext: plaintext,
            format: format  // 将输出格式发送给后端
        })
    })
    .then(response => {
        if (!response.ok) {
            throw new Error('Network response was not ok');
        }
        return response.json();
    })
    .then(data => {
        if (data.error) {
            alert(data.error);
        } else {
            console.log('CBC加密结果:', data.result);
            // 显示加密结果在指定的标签中
            document.getElementById("decryptedPlaintextLabel").textContent = `密文: ${data.result}`;
        }
    })
    .catch(error => {
        console.error('Error:', error);
    });
}






