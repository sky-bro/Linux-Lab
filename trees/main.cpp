#include <iostream>
#include <stack>
#include <vector>
#include <queue>
#include <algorithm>

/*
 * queue<int> q;
 * q.push(v);
 * q.pop(); 队列第一个元素
 * q.front();
 * q.back();
*/

using namespace std;

struct Node{
    int value;
    int:32;
    Node* rightchild;
    Node* leftchild;
    Node(int v){
        value = v;
        rightchild = nullptr;
        leftchild = nullptr;
    }
};

class Tree{

public:
    Tree(int val){
        root = new Node(val);
    }
    Tree(){
        root = nullptr;
    }
    bool insert(int val, Node* rt=nullptr){
        if (!root){
            root = new Node(val);
            return true;
        }
        if (!rt){
            rt = root;
        }
        if (rt->value > val){
            if (!rt->leftchild){
                rt->leftchild = new Node(val);
                return true;
            }
            return insert(val, rt->leftchild);
        } else if(rt->value < val){
            if (!rt->rightchild){
                rt->rightchild = new Node(val);
                return true;
            }
            return insert(val, rt->rightchild);
        } else {
            return false;
        }
    }

    void preOrder(){
        Node *pn = root;
        stack<Node *> stk;
        stk.push(pn);
        while(!stk.empty()){
            pn = stk.top(); stk.pop();
            cout<<pn->value<<" ";
            if (pn->rightchild) stk.push(pn->rightchild);
            if (pn->leftchild) stk.push(pn->leftchild);
        }
    }

    void preOrder2(){
        Node *pn = root;
        stack<Node *> stk;
        while(pn||!stk.empty()){
            while(pn){
                stk.push(pn);
                cout<<pn->value<<" ";
                pn = pn->leftchild;
            }
            if (!stk.empty()){
                pn = stk.top();stk.pop();
                pn = pn->rightchild;
            }
        }
    }

    void inOrder(){
        Node *pn = root;
        stack<Node *> stk;
        while(pn||!stk.empty()){
            while(pn){
                stk.push(pn);
                pn = pn->leftchild;
            }
            if(!stk.empty()){
                pn = stk.top();stk.pop();
                cout<<pn->value<<" ";
                pn = pn->rightchild;
            }
        }
    }

    void postOrder(){
        Node *pn = root;
        stack<Node *> stk;
        stk.push(pn);
        stk.push(pn);
        while(!stk.empty()){
            pn = stk.top(); stk.pop();
            if (!stk.empty()&&pn==stk.top()){
                if(pn->rightchild) stk.push(pn->rightchild), stk.push(pn->rightchild);
                if(pn->leftchild) stk.push(pn->leftchild), stk.push(pn->leftchild);
            }
            else {
                cout<<pn->value<<" ";
            }
        }
    }

    Tree& operator=(const Tree& rhs){

    }

    ~Tree(){
        freeRoot(root);
    }

private:
    Node * root;
    void freeRoot(Node* rt){
        if (!rt){
            return;
        }
        freeRoot(rt->rightchild);
        freeRoot(rt->leftchild);
        delete rt;
        rt = nullptr;
    }
};

int main()
{
    int x;
    Tree tree = Tree();
    while(cin>>x && x!=-1){
        tree.insert(x);
    }
    tree.postOrder();
    cout<<endl;
    tree.preOrder();
    return 0;
}
