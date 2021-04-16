### PE-Tools  
一个PE工具，能够解析PE结构和PE文件的加壳与脱壳。
#### 编译环境
Arch: x86  
IDE: VS2019  
#### 注意事项 
1. SDL检查和符合模式需要选择否。
2. Shell项目需要关闭随机基址(ASLR)。
#### 具体功能
1. 解析PE结构，显示PE头、节区和数据目录信息。  
2. 对PE文件进行加壳，将Shell.exe和PETools.exe放在同一文件夹即可加壳。
3. 对加壳后的文件进行脱壳，能够还原文件。
#### 加壳原理
1. 将源PE文件加密后添加到Shell.exe的新建节后。
2. Shell.exe读取最后一个节的数据并解密。
3. 以挂起的方式创建一个傀儡进程，卸载掉进程的内容。
4. 使用WriteProcessMemory注入源程序到傀儡进程，设置ThreadContext，最后恢复线程执行源程序。
#### 运行效果
##### 主界面：  
![image](https://user-images.githubusercontent.com/55991643/115062794-5098ef00-9f1d-11eb-9c76-49b2c62bce0e.png)
##### 解析PE结构：  
![image](https://user-images.githubusercontent.com/55991643/115061486-d1ef8200-9f1b-11eb-8697-6eff875c1922.png)  
##### 加壳：
此处以SpaceSniffer.exe为例：  
![image](https://user-images.githubusercontent.com/55991643/115061769-27c42a00-9f1c-11eb-9ffd-8f2d3bf2df39.png)
##### 加壳程序运行：
![image](https://user-images.githubusercontent.com/55991643/115061921-53471480-9f1c-11eb-97c5-0605683d0c8b.png)
![image](https://user-images.githubusercontent.com/55991643/115062297-c94b7b80-9f1c-11eb-9e6e-b0f2a9f27544.png)
![image](https://user-images.githubusercontent.com/55991643/115062044-7a054b00-9f1c-11eb-8e15-b097cf798a8c.png)
##### 脱壳：
![image](https://user-images.githubusercontent.com/55991643/115062660-2f380300-9f1d-11eb-84b2-dd9d8e8a22bd.png)
![image](https://user-images.githubusercontent.com/55991643/115062743-41b23c80-9f1d-11eb-9ecf-ecc180b53650.png)


