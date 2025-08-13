check漏洞库
1、特权校验对象可以修改或者校验不严格/特权绕过
	当一些代表特殊标志位（如bool、int、string、token类型等）的变量，是作为if或者函数校验值时，如果标志位的信息可控/可绕过，或者无法对错误的校验值进行拒绝的错误，如下例：
校验对象可控：

class A{
  var key; 
  bool mPrivilege; 
  
  func change (var t){
    
  mPrivilege = t or true;//即能将mPrivilege设置为true
    
  }
  
}

在某个时刻调用 change（true）

func Privilege (A a){
	
  //因为调用了change（true），此时m Privilege一定为true
  
  if(mPrivilege){
    givePrivilege();//给予特权
    }
  
}//总结：校验位值是用户可控的


校验绕过或校验不严格（即没有对不合格的key做出拒绝和覆盖）：


class A{
  var key; 
  bool mPrivilege; 
  
  func change (bool t){
  mPrivilege = t;
  }
  
}

攻击者可以构造一个mPrivilege为true的A对象，key为任意非法对象

func Privilege (A a){

  if(check(key)==true){ //校验通过
    a.change(true); 
    }else	{
     do nothing； //检测到key为非法对象，但是不去修改对应的标志位
  }
  
  if(mPrivilege){
    givePrivilege();//给予特权
    }
  
}//总结：没有对校验不成功的情况做合理的拒绝/错误回应
  


2、java/安卓序列化/反序列化漏洞
	java/安卓中存在多种能够反序列化的类，如果这些类的反序列化函数或者序列化函数中有敏感动作，如给予类特权，读取写入任意信息、执行任意代码、构造可控输入等，攻击者就可以通过序列化或者反序列化来进行提权或者其他恶意操作。

class a{
  
   bool mPrivilege; //特殊权限标志位
   binder token //特殊权限标志位
  
    void readFromParcelImpl(Parcel parcel){
    
      dosome(){
        mPrivilege=true
          set(token)
      }//高危操作，包括不限于给予类特权，读取写入任意信息、执行任意代码、构造可控输入
    }
  
  void  writeToParcel (Parcel dest, int flags) {
    
      dosome(){
        mPrivilege=true
            set(token)
      }//高危操作，包括不限于给予类特权，读取写入任意信息、执行任意代码、能构造可控输入
  }
  
  
  
  }

3、状态污染漏洞状态污染漏洞

if (mayAssociateWithoutPrompt(callingPackage, userId)) {
    Slog.i(LOG_TAG, "setSkipPrompt(true)");
    request.setSkipPrompt(true);  // 只在条件为true时设置
}
// 没有else分支来重置skipPrompt状态！

攻击步骤
构造恶意AssociationRequest对象：
// 攻击者预先构造的恶意request
AssociationRequest maliciousRequest = new AssociationRequest.Builder()
    .setSingleDevice(true)
    .build();
// 通过反射或其他方式设置skipPrompt为true
maliciousRequest.setSkipPrompt(true);  // 恶意预设状态
绕过授权检查：

// 当攻击者调用associate方法时：
associate(maliciousRequest, callback, attackerPackage);

// 即使mayAssociateWithoutPrompt(attackerPackage, userId)返回false
// 代码也不会执行setSkipPrompt(true)
// 但更关键的是，也不会执行setSkipPrompt(false)来重置状态！
利用污染状态：
// 在后续的设备发现流程中：
service.startDiscovery(request, callingPackage, callback, future);
// request对象仍然保持skipPrompt=true的状态
// 系统可能会跳过用户确认对话框

修复方式：
如将他设置为request.setSkipPrompt(mayAssociateWithoutPrompt（userid）)后，就是安全的，因为mayAssociateWithoutPrompt（userid）是安全的，
所以request.setSkipPrompt(mayAssociateWithoutPrompt（userid）)也是安全的
