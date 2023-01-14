import sys 

from PyQt5.QtWidgets import *

from PyQt5.QtGui import *

from PyQt5.QtCore import *

from PyQt5.QtWebEngineWidgets import *

from PyQt5.QtWebEngine import*

from PyQt5.QtNetwork import*

from PyQt5.QtWebEngineCore import*

import adblockparser

from adblockparser import *

from google.oauth2.credentials import Credentials

from googleapiclient.discovery import build

from PyQt5.QtNetwork import QSslSocket, QSslCertificate

import socks
   
API_KEY = "AIzaSyACagUZar-lS09LIHZJMimEFJcKH0wm6j4" # Google Safe Browsing API Key

def check_url_safety(url):
    # Create a client object
    service = build("safebrowsing", "v4", credentials=Credentials.from_authorized_user_info(info=None, client_id=API_KEY))

    # Call the 'threatMatches.find' method of the Safe Browsing API
    response = service.threatMatches().find(
        body={
            "client": {
                "clientId":      "Safe Navigator",
                "clientVersion": "1.0.0"
            },
            "threatInfo": {
                "threatTypes":      ["MALWARE", "SOCIAL_ENGINEERING", "THREAT_TYPE_UNWANTED_SOFTWARE"],
                "platformTypes":    ["WINDOWS"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [
                    {"url": url}
                ]
            }
        }
    ).execute()

    # Check the response for matches
    if response.get("matches"):
        return True
    else:
        return False


class WebEngineUrlRequestInterceptor(QWebEngineUrlRequestInterceptor):
    def __init__(self, parent=None):
        super().__init__(parent)
        with open("ad_servers.txt", encoding="utf-8") as f:
            raw_rules = f.readlines()
            self.rules = adblockparser.AdblockRules(raw_rules)

    def interceptRequest(self, info):
        url = info.requestUrl().toString()
        if self.rules.should_block(url) or check_url_safety(url):
            print("block::::::::::::::::::::::", url)
            info.block(True)
            return
        
        url = info.requestUrl()
        if url.scheme() == "https":
            sslSocket = QSslSocket()
            sslSocket.ignoreSslErrors()
            sslSocket.connectToHostEncrypted(url.host(), url.port())
            if not sslSocket.waitForEncrypted():
                print("SSL/TLS certificate validation failed for " + url.toString())
                info.block(True)
                return
            cert = sslSocket.peerCertificate()
            if not cert.isValid() or cert in QSslCertificate.blacklistedCertificates():
                print("Invalid or blacklisted SSL/TLS certificate for " + url.toString())
                info.block(True)
                return


class MyNetworkAccessManager(QNetworkAccessManager):
    def __init__(self, parent=None):
        super().__init__(parent)

    def createRequest(self, operation, request, device=None):
        if request.url().scheme() == "https":
            sslConfig = QSslConfiguration.defaultConfiguration()
            sslConfig.setPeerVerifyMode(QSslSocket.VerifyPeer)
            request.setSslConfiguration(sslConfig)
        return super(MyNetworkAccessManager, self).createRequest(operation, request, device)


class AddressBar(QLineEdit):
    def __init__(self):
        super().__init__()

    def mousePressEvent(self, e):
        self.selectAll()
    

class App(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Safe Navigator")
        self.CreateApp()
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self.setWindowState(Qt.WindowMaximized)
        self.setWindowIcon(QIcon("icons/logo.png"))


    def CreateApp(self):

        #connect to free proxy
        '''proxy = QNetworkProxy()
        proxy.setType(QNetworkProxy.Socks5Proxy)
        proxy.setHostName("") 
        proxy.setPort()
        QNetworkProxy.setApplicationProxy(proxy)'''

        # Create the main layout for the window
        self.layout = QVBoxLayout()

        # Create the central widget and set its layout
        self.central_widget = QWidget(self)
        self.setCentralWidget(self.central_widget)
        self.central_widget.setLayout(self.layout)
        self.layout.setContentsMargins(0,0,0,0)
        
    
        # Create the tab bar and add it to the main layout
        self.tabbar = QTabBar(movable=True, tabsClosable=True)
        self.tabbar.setObjectName("TabBar")
        self.tabbar.tabCloseRequested.connect(self.CloseTab)
        self.tabbar.tabBarClicked.connect(self.SwitchTab)
        self.tabbar.setDrawBase(False)
        self.layout.addWidget(self.tabbar)

        self.tabbar.setCurrentIndex(0)
        
        # Create the web view and page
        self.webview = QWebEngineView()
        self.page = self.webview.page()
        #SSL/TSL encryption
        self.webview.setPage(QWebEnginePage(MyNetworkAccessManager(self.page)))

        #Keyboard shortcut to Add tab
        self.shortcutNewTab = QShortcut(QKeySequence("Ctrl+T"), self)
        self.shortcutNewTab.activated.connect(self.AddTab)

        #Keyboard shortcut to Reload tab
        self.shortcutReloadTab = QShortcut(QKeySequence("Ctrl+R"), self)
        self.shortcutReloadTab.activated.connect(self.ReloadPage)

        #keyboard shortcut to go back
        self.shortcutBackTab = QShortcut(QKeySequence("Ctrl+B"), self)
        self.shortcutBackTab.activated.connect(self.GoBack)

        #Keyboard shortcut to go forward
        self.shortcutForwardTab = QShortcut(QKeySequence("Ctrl+F"), self)
        self.shortcutForwardTab.activated.connect(self.GoForward)

        #Keyboard shortcut for dev tools pop up
        self.shortcutForwardTab = QShortcut(QKeySequence("Ctrl+I"), self)
        self.shortcutForwardTab.activated.connect(self.show_popup)


        #keep track of tabs
        self.tabCount = 0
        self.tabs = []

        #Create AddressBar
        self.Toolbar = QWidget()
        self.Toolbar.setObjectName("Toolbar")
        self.ToolbarLayout = QHBoxLayout()
        self.addressbar = AddressBar()

        #Set Toolbar Buttons
        self.BackButton = QPushButton()
        button_size = QSize(35, 35) 
        self.BackButton.setFixedSize(button_size)
        back_button_icon = QIcon("icons/back.png")
        icon_size = QSize(40, 40)  # width and height in pixels
        self.BackButton.setIcon(back_button_icon)
        self.BackButton.setIconSize(icon_size)
        self.BackButton.clicked.connect(self.GoBack)

        self.ForwardButton = QPushButton()
        button_size6 = QSize(35, 35) 
        self.ForwardButton.setFixedSize(button_size6)
        back_button_icon6 = QIcon("icons/forward.png")
        icon_size6 = QSize(40, 40)  # width and height in pixels
        self.ForwardButton.setIcon(back_button_icon6)
        self.ForwardButton.setIconSize(icon_size6)
        self.ForwardButton.clicked.connect(self.GoForward)

        self.ReloadButton = QPushButton()
        button_size3 = QSize(35, 35) 
        self.ReloadButton.setFixedSize(button_size3)
        back_button_icon3 = QIcon("icons/reload.png")
        icon_size3 = QSize(30, 30)  # width and height in pixels
        self.ReloadButton.setIcon(back_button_icon3)
        self.ReloadButton.setIconSize(icon_size3)
        self.ReloadButton.clicked.connect(self.ReloadPage)

        self.DevButton = QPushButton()
        button_size7 = QSize(35, 35) 
        self.DevButton.setFixedSize(button_size7)
        back_button_icon7 = QIcon("icons/dev_tools.png")
        icon_size7 = QSize(30, 30)  # width and height in pixels
        self.DevButton.setIcon(back_button_icon7)
        self.DevButton.setIconSize(icon_size7)
        self.DevButton.clicked.connect(self.show_popup)

        #New tab Button
        self.AddTabButton = QPushButton()
        button_size4 = QSize(45, 45) 
        self.AddTabButton.setFixedSize(button_size4)
        back_button_icon4 = QIcon("icons/add.png")
        icon_size4 = QSize(40, 40)  # width and height in pixels
        self.AddTabButton.setIcon(back_button_icon4)
        self.AddTabButton.setIconSize(icon_size4)
        self.addressbar.returnPressed.connect(self.BrowseTo)
        self.AddTabButton.clicked.connect(self.AddTab)

        #Proxy Button
        self.ProxyButton = QPushButton()
        button_size5 = QSize(45, 45) 
        self.ProxyButton.setFixedSize(button_size5)
        back_button_icon5 = QIcon("icons/croxy.png")
        icon_size5 = QSize(40, 40)  # width and height in pixels
        self.ProxyButton.setIcon(back_button_icon5)
        self.ProxyButton.setIconSize(icon_size5)
        self.ProxyButton.clicked.connect(self.BrowseToProxy)

        self.Toolbar.setLayout(self.ToolbarLayout)
        self.ToolbarLayout.addWidget(self.BackButton)
        self.ToolbarLayout.addWidget(self.ForwardButton)
        self.ToolbarLayout.addWidget(self.ReloadButton)
        self.ToolbarLayout.addWidget(self.DevButton)
        self.ToolbarLayout.addWidget(self.addressbar)
        self.ToolbarLayout.addWidget(self.AddTabButton)
        self.ToolbarLayout.addWidget(self.ProxyButton)

        
        #set main view
        self.container = QWidget()
        self.container.layout = QStackedLayout()
        self.container.setLayout(self.container.layout)
        self.container.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Preferred)
        self.container.setGeometry(0, 0, self.width(), self.height())

        # Set style sheet for address bar, toolbar, and container widget
        self.addressbar.setStyleSheet("margin: 0; padding: 0;")
        self.Toolbar.setStyleSheet("margin: 0; padding: 0;")
        self.container.setStyleSheet("margin: 0; padding: 0;")
        self.setStyleSheet("border: none;")
        self.container.setStyleSheet("border: none;")

        #self.layout.addWidget(self.tabbar)
        self.layout.addWidget(self.Toolbar)
        self.layout.addWidget(self.container)
        self.layout.setStretchFactor(self.tabbar, 0)
        self.layout.setStretchFactor(self.Toolbar, 0)
        self.layout.setStretchFactor(self.container, 1)

        # Set spacing of layouts
        self.layout.setSpacing(0)
        self.ToolbarLayout.setSpacing(0)
        self.container.layout.setSpacing(0)

        desktop_widget = QApplication.desktop()
        screen_rect = desktop_widget.availableGeometry()
        self.setMinimumSize(screen_rect.width(), screen_rect.height())
        self.show() 

        
    def CloseTab(self, i):
        self.tabbar.removeTab(i)
        self.container.layout.removeWidget(self.tabs[i])
        self.tabs.pop(i)
        self.tabCount -= 1
        if len(self.tabs) == 0:
            self.close()

    def AddTab(self):
        i = self.tabCount
        self.tabs.append(QWidget())
        self.tabs[i].layout = QVBoxLayout()
        self.tabs[i].layout.setContentsMargins(0,0,0,0)

        #For tab switching
        self.tabs[i].setObjectName("tab" + str(i))

        #Open Webpage
        interceptor = WebEngineUrlRequestInterceptor()
        view = QWebEngineView()

        #ad block 
        view.page().profile().defaultProfile().setUrlRequestInterceptor(interceptor)

        view.page().setFeaturePermission(view.url(), QWebEnginePage.MediaAudioVideoCapture, QWebEnginePage.PermissionGrantedByUser)
        #Block Pop-ups
        view.page().setFeaturePermission(view.url(), QWebEnginePage.Notifications, QWebEnginePage.PermissionDeniedByUser)

        view.page().runJavaScript("window.scrollTo(0, document.body.scrollHeight);")
        view.page().runJavaScript("document.querySelector('html').style.height = '100%';")
        view.page().runJavaScript("document.querySelector('body').style.height = '100%';")
        view.page().runJavaScript("document.querySelector('html').style.overflowY = 'scroll';")
        view.page().runJavaScript("document.querySelector('body').style.overflowY = 'scroll';")

        self.tabs[i].content = view

        self.tabs[i].content.load(QUrl.fromUserInput("https://duckduckgo.com/"))

        # cookie Block
        self.tabs[i].content.page().profile().setHttpCacheType(QWebEngineProfile.NoCache)
        self.tabs[i].content.page().profile().setPersistentCookiesPolicy(QWebEngineProfile.NoPersistentCookies)
        
        self.tabs[i].content.setMinimumSize(self.size())
        self.tabs[i].content.titleChanged.connect(lambda : self.SetTabContent(i, "title"))
        self.tabs[i].content.iconChanged.connect(lambda : self.SetTabContent(i, "icon"))
        self.tabs[i].content.urlChanged.connect(lambda : self.SetTabContent(i, "url"))
        
        self.tabs[i].layout.addWidget(self.tabs[i].content)

        #Set Top level tab from [] to layout
        self.tabs[i].setLayout(self.tabs[i].layout)

        #Add tab to top level stacked widget
        self.container.layout.addWidget(self.tabs[i])
        self.container.layout.setCurrentWidget(self.tabs[i])

        #Set tab at top of screen
        self.tabbar.addTab("New Tab")
        self.tabbar.setTabData(i,{"object":"tab" + str(i), "initial": int(i)})
        self.tabbar.setCurrentIndex(i)

        self.tabCount += 1

        
    def SwitchTab(self, i):
        #Switch to tab
        if self.tabbar.tabData(i):
            tab_data = self.tabbar.tabData(i)
            tab_name = tab_data["object"]
            tab_content = self.findChild(QWidget, tab_name)

            #Set the current widget to the corresponding tab
            self.container.layout.setCurrentWidget(tab_content)
            new_url = tab_content.content.url().toString()
            self.addressbar.setText(new_url)

    
    def BrowseTo(self):
        try:
 
            text = self.addressbar.text()
            i = self.tabbar.currentIndex()
            if i < 0 or i >= len(self.tabs):
                raise IndexError
            wv = self.tabs[i].content
            if "http" not in text:
                if "." not in text:
                    url = "https://duckduckgo.com/?q=" + text + "&ia=web"

                else:
                    url = "https://" + text

            else:
                url = text
            
            #pop-up block
            wv.page().setFeaturePermission(QUrl(url), QWebEnginePage.Notifications, QWebEnginePage.PermissionDeniedByUser)

            wv.page().setFeaturePermission(QUrl(url), QWebEnginePage.MediaAudioVideoCapture, QWebEnginePage.PermissionGrantedByUser)
            #add block
            interceptor = WebEngineUrlRequestInterceptor()
            wv.page().profile().defaultProfile().setUrlRequestInterceptor(interceptor)

            wv.load(QUrl.fromUserInput(url))

            #cookie block
            wv.page().profile().setHttpCacheType(QWebEngineProfile.NoCache)
            wv.page().profile().setPersistentCookiesPolicy(QWebEngineProfile.NoPersistentCookies)
   
        except IndexError:
            print("Error: Invalid tab index")


    def BrowseToProxy(self):
        try:
            i = self.tabbar.currentIndex()
            if i < 0 or i >= len(self.tabs):
                    raise IndexError
            wv = self.tabs[i].content
            url = "https://www.croxyproxy.com/"

            #pop-up block
            wv.page().setFeaturePermission(QUrl(url), QWebEnginePage.Notifications, QWebEnginePage.PermissionDeniedByUser)
            wv.page().runJavaScript("window.scrollTo(0, document.body.scrollHeight);")
            wv.page().runJavaScript("document.querySelector('html').style.height = '100%';")
            wv.page().runJavaScript("document.querySelector('body').style.height = '100%';")
            wv.page().runJavaScript("document.querySelector('html').style.overflowY = 'scroll';")
            wv.page().runJavaScript("document.querySelector('body').style.overflowY = 'scroll';")

            wv.page().setFeaturePermission(QUrl(url), QWebEnginePage.MediaAudioVideoCapture, QWebEnginePage.PermissionGrantedByUser)
            #add block
            interceptor = WebEngineUrlRequestInterceptor()
            wv.page().profile().defaultProfile().setUrlRequestInterceptor(interceptor)

            wv.load(QUrl.fromUserInput(url))

            #cookie block
            wv.page().profile().setHttpCacheType(QWebEngineProfile.NoCache)
            wv.page().profile().setPersistentCookiesPolicy(QWebEngineProfile.NoPersistentCookies)

        except IndexError:
            print("Error: Invalid tab index")

    
    def SetTabContent(self, i, type):
        tab_name = self.tabs[i].objectName()
        #tab1
        count = 0
        running = True

        current_tab = self.tabbar.tabData(self.tabbar.currentIndex())["object"]

        if(current_tab == tab_name and type == "url"):
            newUrl = self.findChild(QWidget, tab_name).content.url().toString()
            self.addressbar.setText(newUrl)
            return False

        while running:
            tab_data_name = self.tabbar.tabData(count)
            if count >= 99:
                running = False

            if tab_name == tab_data_name["object"]:
                if type == "title":
                    newTitle = self.findChild(QWidget, tab_name).content.title()
                    self.tabbar.setTabText(count, newTitle)
                elif type == "icon":
                    newIcon = self.findChild(QWidget, tab_name).content.icon()
                    self.tabbar.setTabIcon(count, newIcon)

                running = False
            else:
                count += 1


    def GoBack(self):
        activeIndex = self.tabbar.currentIndex()
        tab_name = self.tabbar.tabData(activeIndex)["object"]
        tab_content = self.findChild(QWidget, tab_name).content
        tab_content.back()


    def GoForward(self):
        activeIndex = self.tabbar.currentIndex()
        tab_name = self.tabbar.tabData(activeIndex)["object"]
        tab_content = self.findChild(QWidget, tab_name).content
        tab_content.forward()

    def ReloadPage(self):
        activeIndex = self.tabbar.currentIndex()
        tab_name = self.tabbar.tabData(activeIndex)["object"]
        tab_content = self.findChild(QWidget, tab_name).content
        tab_content.reload()
    
    def show_popup(self):
        dialog = QDialog(self)
        dialog.setWindowTitle("Safe Navigator Developer Tools")
        self.setWindowIcon(QIcon("icons/logo.png"))
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        
        i = self.tabbar.currentIndex()
        self.tabs[i].dev_tools = QWebEngineView()
        self.tabs[i].dev_tools.page().setInspectedPage(self.tabs[i].content.page())
        # Create a vertical layout for the dialog
        layout = QVBoxLayout()

        # Add the Dev Tools to the pop up layout
        layout.addWidget(self.tabs[i].dev_tools)

        # Set the layout for the dialog
        dialog.setLayout(layout)

        dialog.exec_()

        
if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setApplicationName("Safe Navigator")

    window = App()
    window.AddTab()

    with open("style.css", "r") as style:
        app.setStyleSheet(style.read())

    sys.exit(app.exec_())





















