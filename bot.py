import discord
import requests
import base64
import time
import os
from datetime import datetime, timedelta
from discord.ext import commands
from flask import Flask
from threading import Thread

# ==========================================
# 第一部分：防斷線機制 (Render 專用)
# ==========================================
app = Flask('')

@app.route('/')
def home():
    return "I am alive! Security Bot is running."

def run_flask():
    # Render 會自動分配 Port，預設使用 8080
    app.run(host='0.0.0.0', port=8080)

def keep_alive():
    t = Thread(target=run_flask)
    t.start()

# ==========================================
# 第二部分：機器人核心設定
# ==========================================

# 讀取雲端鑰匙
DISCORD_TOKEN = os.getenv('DISCORD_TOKEN')
VIRUSTOTAL_KEY = os.getenv('VIRUSTOTAL_KEY')
LOG_CHANNEL_ID = os.getenv('LOG_CHANNEL_ID') 

intents = discord.Intents.default()
intents.message_content = True 
bot = commands.Bot(command_prefix='!', intents=intents)

def scan_url(url):
    """
    回傳：(報告文字, 顏色, 是否攔截)
    """
    print(f"正在掃描網址: {url}")
    try:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        headers = {"accept": "application/json", "x-apikey": VIRUSTOTAL_KEY}
        
        requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, data={"url": url})
        time.sleep(2)
        response = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers)
        
        if response.status_code == 200:
            data = response.json()
            stats = data['data']['attributes']['last_analysis_stats']
            malicious = stats['malicious']
            
            # 紅燈：3家以上 -> 攔截
            if malicious >= 3:
                return (f"🔴 危險警告 (惡意判定: {malicious} 家)", 0xff0000, True)
            # 黃燈：2家 -> 攔截
            elif malicious == 2:
                return (f"🟡 風險提示 (惡意判定: {malicious} 家)", 0xffa500, True)
            # 綠燈：0~1家 -> 放行
            else:
                return (f"🟢 安全通過 (惡意判定: {malicious} 家)", 0x00ff00, False)
        else:
            return (f"❌ 檢測失敗", 0x95a5a6, False)
    except Exception as e:
        return (f"錯誤: {str(e)}", 0x000000, False)

@bot.event
async def on_ready():
    print(f'機器人 {bot.user} 上線中 (公開警告 + 後台全紀錄)')
    await bot.change_presence(activity=discord.Activity(type=discord.ActivityType.watching, name="是否有毒連結"))

@bot.event
async def on_message(message):
    if message.author == bot.user: return

    if "http" in message.content:
        words = message.content.split()
        for word in words:
            if word.startswith("http"):
                
                # 1. 執行掃描
                result_text, color_code, need_block = scan_url(word)
                
                # 2. 前台處理 (公開頻道)
                if need_block:
                    try:
                        # 動作 A: 刪除原始訊息
                        await message.delete()
                        
                        # 動作 B: 發送公開警告訊息
                        warning_msg = (
                            f"🚫 **系統攔截警告**\n"
                            f"{message.author.mention} 張貼的連結被偵測為 **不安全**，已自動移除！\n"
                            f"(`{result_text}`)"
                        )
                        await message.channel.send(warning_msg)
                        
                    except discord.Forbidden:
                        await message.channel.send(f"⚠️ **危險！** 偵測到惡意連結但無權限刪除！\n{message.author.mention} 請不要點擊！")
                else:
                    try:
                        # 安全：給個勾勾就好，不吵人
                        await message.add_reaction("✅")
                    except:
                        pass

                # 3. 後台紀錄 (送到指定的 LOG_CHANNEL_ID)
                if LOG_CHANNEL_ID:
                    try:
                        target_channel = bot.get_channel(int(LOG_CHANNEL_ID))
                        if target_channel:
                            # 取得台灣時間 (UTC+8)
                            tw_time = datetime.utcnow() + timedelta(hours=8)
                            time_str = tw_time.strftime("%Y-%m-%d %H:%M")

                            embed = discord.Embed(
                                title="📝 連結掃描紀錄",
                                description=f"來源頻道: <#{message.channel.id}>",
                                color=color_code
                            )
                            embed.add_field(name="📅 時間", value=time_str, inline=True)
                            embed.add_field(name="👤 發送者", value=f"{message.author.name}", inline=True)
                            embed.add_field(name="📊 結果", value=result_text, inline=False)
                            embed.add_field(name="🔗 連結內容", value=f"```\n{word}\n```", inline=False)
                            
                            await target_channel.send(embed=embed)
                    except Exception as e:
                        print(f"紀錄失敗: {e}")

    await bot.process_commands(message)

# ==========================================
# 第三部分：啟動程式
# ==========================================
if __name__ == "__main__":
    # 1. 先啟動假網站
    keep_alive()
    
    # 2. 再啟動機器人
    if DISCORD_TOKEN and VIRUSTOTAL_KEY:
        bot.run(DISCORD_TOKEN)
    else:
        print("錯誤：找不到 Token 或 Key，請檢查環境變數設定。")
