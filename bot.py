import discord
import requests
import base64
import time
import os  # 雲端專用模組
from discord.ext import commands

# ==========================================
# 【雲端設定區】
# 自動去讀取 Render 後台設定的鑰匙
# ==========================================
DISCORD_TOKEN = os.getenv('DISCORD_TOKEN')
VIRUSTOTAL_KEY = os.getenv('VIRUSTOTAL_KEY')

# ==========================================

# 設定機器人權限
intents = discord.Intents.default()
intents.message_content = True 

bot = commands.Bot(command_prefix='!', intents=intents)

def scan_url(url):
    """
    核心掃描功能 (調整後的紅綠燈版)
    """
    print(f"正在掃描網址: {url}")
    try:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        headers = {"accept": "application/json", "x-apikey": VIRUSTOTAL_KEY}
        
        # 送出掃描請求
        requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, data={"url": url})
        
        # 等待報告生成
        time.sleep(2)
        response = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers)
        
        if response.status_code == 200:
            data = response.json()
            stats = data['data']['attributes']['last_analysis_stats']
            malicious = stats['malicious']
            
            # === 【新版判斷邏輯】 ===
            
            # 紅燈：3 家以上 (維持高風險認定)
            if malicious >= 3:
                return f"🔴 **【危險警告】千萬不要點！**\n這網址被 **{malicious}** 家廠商判定為惡意！有極高風險。"
            
            # 黃燈：剛好 2 家 (你的新標準)
            elif malicious == 2:
                return f"🟡 **【有點可疑】請小心**\n有 **{malicious}** 家廠商覺得怪怪的，如果是陌生連結建議不要點。"
            
            # 綠燈：0 家 或 1 家 (你的新標準：容許1家誤判)
            else:
                msg = f"🟢 **【安全通過】**\n目前檢測看起來是乾淨的。"
                if malicious == 1:
                    msg += " (有 1 家廠商判定惡意，但通常是誤判，不必擔心)"
                return msg
                
        else:
            return f"❌ 查詢失敗 (錯誤代碼: {response.status_code})，可能 API 次數用完了。"
            
    except Exception as e:
        return f"程式發生錯誤: {str(e)}"

@bot.event
async def on_ready():
    print(f'機器人已上線: {bot.user}')
    print(f'目前模式: 雲端免費版 (判定標準：綠燈<=1, 黃燈=2, 紅燈>=3)')

@bot.event
async def on_message(message):
    # 避免機器人自言自語
    if message.author == bot.user:
        return

    # 只要訊息包含網址，就直接服務
    if "http" in message.content:
        words = message.content.split()
        for word in words:
            if word.startswith("http"):
                status_msg = await message.channel.send(f"🔍 發現網址，正在幫 **{message.author.name}** 掃描 `{word}`...")
                result = scan_url(word)
                await status_msg.edit(content=result)

    await bot.process_commands(message)

# 啟動機器人
if DISCORD_TOKEN is None or VIRUSTOTAL_KEY is None:
    print("【注意】偵測不到雲端金鑰！(若是上傳 Render 請忽略此訊息)")
else:
    bot.run(DISCORD_TOKEN)
