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
# 第一部分：防斷線機制
# ==========================================
app = Flask('')

@app.route('/')
def home():
    return "I am alive! Security Bot is running."

def run_flask():
    app.run(host='0.0.0.0', port=8080)

def keep_alive():
    t = Thread(target=run_flask)
    t.start()

# ==========================================
# 第二部分：機器人設定
# ==========================================
DISCORD_TOKEN = os.getenv('DISCORD_TOKEN')
VIRUSTOTAL_KEY = os.getenv('VIRUSTOTAL_KEY')
LOG_CHANNEL_ID = os.getenv('LOG_CHANNEL_ID') 

intents = discord.Intents.default()
intents.message_content = True 
bot = commands.Bot(command_prefix='!', intents=intents)

# 設定 Log 討論串的固定名稱
LOG_THREAD_NAME = "🛡️-掃描紀錄-Log"

def scan_url(url):
    """回傳：(報告文字, 顏色, 是否攔截)"""
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
            
            if malicious >= 3:
                return (f"🔴 危險警告 (惡意判定: {malicious} 家)", 0xff0000, True)
            elif malicious == 2:
                return (f"🟡 風險提示 (惡意判定: {malicious} 家)", 0xffa500, True)
            else:
                return (f"🟢 安全通過 (惡意判定: {malicious} 家)", 0x00ff00, False)
        else:
            return (f"❌ 檢測失敗", 0x95a5a6, False)
    except Exception as e:
        return (f"錯誤: {str(e)}", 0x000000, False)

@bot.event
async def on_ready():
    print(f'機器人 {bot.user} 上線中 (集中式 Log 模式)')
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
                # 如果是危險連結：刪除並警告
                if need_block:
                    try:
                        await message.delete()
                        warning_msg = (
                            f"🚫 **系統攔截**\n"
                            f"{message.author.mention} 的連結被偵測為 **不安全**，已移除！\n"
                            f"(`{result_text}`)"
                        )
                        await message.channel.send(warning_msg)
                    except discord.Forbidden:
                        await message.channel.send(f"⚠️ 無權限刪除惡意連結！\n{message.author.mention} 請勿點擊！")
                
                # 如果是安全連結：給個勾勾就好，保持版面乾淨
                else:
                    try:
                        await message.add_reaction("✅")
                    except:
                        pass

                # 3. 後台紀錄 (集中到同一個討論串)
                try:
                    # 決定 Log 要發在哪個頻道 (如果有設定 LOG_CHANNEL_ID 就去那，沒有就在當前頻道)
                    if LOG_CHANNEL_ID:
                        log_target_channel = bot.get_channel(int(LOG_CHANNEL_ID))
                    else:
                        log_target_channel = message.channel

                    if log_target_channel:
                        # === 關鍵邏輯：尋找或建立 Log 討論串 ===
                        log_thread = None
                        
                        # 先找找看現有的討論串有沒有叫這個名字的
                        for thread in log_target_channel.threads:
                            if thread.name == LOG_THREAD_NAME:
                                log_thread = thread
                                break
                        
                        # 如果找不到，就創建一個新的 (設定為公開討論串)
                        if not log_thread:
                            try:
                                log_thread = await log_target_channel.create_thread(
                                    name=LOG_THREAD_NAME,
                                    type=discord.ChannelType.public_thread
                                )
                            except Exception as e:
                                print(f"無法建立討論串: {e}")
                                # 如果無法建立討論串(例如沒權限)，就直接發在頻道
                                log_thread = log_target_channel

                        # 準備報告內容
                        tw_time = datetime.utcnow() + timedelta(hours=8)
                        embed = discord.Embed(
                            title="📝 連結掃描報告",
                            description=f"來源頻道: <#{message.channel.id}>",
                            color=color_code
                        )
                        embed.add_field(name="📅 時間", value=tw_time.strftime("%Y-%m-%d %H:%M"), inline=True)
                        embed.add_field(name="👤 發送者", value=f"{message.author.name}", inline=True)
                        embed.add_field(name="📊 結果", value=result_text, inline=False)
                        embed.add_field(name="🔗 連結", value=f"```\n{word}\n```", inline=False)
                        
                        # 發送到那個集中討論串
                        await log_thread.send(embed=embed)

                except Exception as e:
                    print(f"紀錄失敗: {e}")

    await bot.process_commands(message)

# ==========================================
# 第三部分：啟動
# ==========================================
if __name__ == "__main__":
    keep_alive()
    if DISCORD_TOKEN and VIRUSTOTAL_KEY:
        bot.run(DISCORD_TOKEN)
    else:
        print("錯誤：找不到 Token 或 Key。")
