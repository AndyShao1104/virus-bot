import discord
import requests
import base64
import time
import asyncio
from discord.ext import commands

# ==========================================
# 【設定區】請務必填回你的鑰匙！
# ==========================================

# 1. Discord 機器人的身分證 (Token)
# 去 Discord Developer Portal 申請
DISCORD_TOKEN = '' 

# 2. VirusTotal 的鑰匙 (API Key)
# 去 VirusTotal 官網申請
VIRUSTOTAL_KEY = ''

# ==========================================

# 設定機器人權限 (一定要開 Message Content)
intents = discord.Intents.default()
intents.message_content = True 

bot = commands.Bot(command_prefix='!', intents=intents)

def scan_url(url):
    """
    核心功能：向 VirusTotal 查詢網址安全性
    """
    print(f"正在掃描網址: {url}")
    try:
        # 1. 網址編碼 (VirusTotal 要求)
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        
        headers = {
            "accept": "application/json",
            "x-apikey": VIRUSTOTAL_KEY
        }
        
        # 2. 送出掃描請求 (確保資料是最新的)
        # 如果是沒見過的網址，這步會觸發新的掃描
        requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, data={"url": url})
        
        # 3. 獲取報告
        # 稍微等待 2 秒讓伺服器處理一下
        time.sleep(2)
        response = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers)
        
        if response.status_code == 200:
            data = response.json()
            stats = data['data']['attributes']['last_analysis_stats']
            
            malicious = stats['malicious']   # 惡意
            suspicious = stats['suspicious'] # 可疑
            harmless = stats['harmless']     # 無害
            undetected = stats['undetected'] # 未偵測到
            total_checked = malicious + suspicious + harmless + undetected
            
            # ==========================================
            # 【新版判斷邏輯：紅黃綠燈號】
            # ==========================================
            
            # 紅燈：3 家以上判定惡意 -> 高機率是病毒/釣魚
            if malicious >= 3:
                return (
                    f"🔴 **【危險警告】千萬不要點！**\n"
                    f"這網址被 **{malicious}** 家防毒軟體判定為惡意網站！\n"
                    f"包含釣魚、詐騙或病毒風險。"
                )
            
            # 黃燈：1~2 家判定惡意 -> 可能是誤判，也可能是新型威脅
            elif malicious > 0:
                return (
                    f"🟡 **【有點可疑】請小心**\n"
                    f"有 **{malicious}** 家廠商覺得怪怪的，但其他大部分覺得沒事。\n"
                    f"建議：如果是知名大網站(如Google)通常是誤判；如果是陌生連結，請不要輸入帳號密碼。"
                )
            
            # 綠燈：0 家判定惡意 -> 安全
            else:
                return (
                    f"🟢 **【安全通過】**\n"
                    f"經由 {total_checked} 家資安廠商檢測，目前看起來是乾淨的。"
                )
                
        else:
            return f"❌ 查詢失敗 (錯誤代碼: {response.status_code})，請檢查 API Key 是否正確。"
            
    except Exception as e:
        return f"程式發生錯誤: {str(e)}"

@bot.event
async def on_ready():
    print(f'---------------------------------------')
    print(f'機器人已登入: {bot.user}')
    print(f'ID: {bot.user.id}')
    print(f'狀態: 監控模式啟動中 (門檻值: >=3 家判定惡意)')
    print(f'---------------------------------------')

@bot.event
async def on_message(message):
    # 避免機器人自己跟自己講話
    if message.author == bot.user:
        return

    # 簡單抓取訊息中的網址 (只要有 http 就觸發)
    if "http" in message.content:
        words = message.content.split()
        for word in words:
            if word.startswith("http"):
                # 發送提示訊息
                status_msg = await message.channel.send(f"🔍 發現網址：`{word}`，正在進行資安掃描...")
                
                # 執行掃描
                result = scan_url(word)
                
                # 編輯原本的訊息顯示結果 (比再發一則新的更乾淨)
                await status_msg.edit(content=result)

    await bot.process_commands(message)

# 啟動機器人
if '貼上你的' in DISCORD_TOKEN or '貼上你的' in VIRUSTOTAL_KEY:
    print("【錯誤】請打開 bot.py，把第 13 行和第 16 行改成你真正的 Token 和 Key！")
else:
    bot.run(DISCORD_TOKEN)