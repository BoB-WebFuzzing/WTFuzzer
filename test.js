const fs = require('fs');

const filePath = 'test.txt';

// 파일을 읽어서 내용을 콘솔에 출력
fs.readFile(filePath, 'utf8', (err, data) => {
  if (err) {
    console.error(`Error reading file: ${err}`);
    return;
  }

  console.log('File content:');
  console.log(data);
});
