import ast
#O módulo ast transforma o código Python numa árvore sintática.

# Ler o código
with open("appVulneravel.py", "r") as f:
    source = f.read()

tree = ast.parse(source)


#Extrair funções
class FunctionVisitor(ast.NodeVisitor):

      def visit_FunctionDef(self, node):
            print("Saída da função FunctionVisitor:")
            print(node.name)


#Contruir call graph
class CallGraphVisitor(ast.NodeVisitor):

        def __init__(self):
              self.current_function = None
              self.graph = {}

            
        
        def visit_FunctionDef(self, node):
              self.current_function = node.name
              #print(node.name)

              if node.name not in self.graph:
                    self.graph[node.name] = []
            
              self.generic_visit(node)


        def visit_Call(self, node):
              if isinstance(node.func, ast.Name):
                    called = node.func.id
                    if self.current_function:
                          self.graph[self.current_function].append(called)
                          self.generic_visit(node)



#Reachability Analysis
#fazemos DFS agora
def reachable(graph, start, target):
      
      visited = set()

      stack = [start]

      while stack:
            current = stack.pop()

            if current == target:
                  print("Função é alcançável:")
                  print(current)
                  return True
            
            if current in visited:
                  continue
            
            visited.add(current)

            stack.extend(graph.get(current, []))

      print(f"Função:", current)
      print("É alcançável ?")  
      return False




#-----------------------------------------------------------------------------------------
#Extrair funções
visitor = FunctionVisitor()
visitor.visit(tree)


#Gerar grafo
visitor = CallGraphVisitor()
visitor.visit(tree)

print(visitor.graph)


#Reachability Analysis
#testing
print(reachable(
            visitor.graph,
            "main",
            "vulnerable"
      )
)


#análise CVE -> função
import json

with open("cves.json") as f:
    cves = json.load(f)

for cve, function in cves.items():

      if reachable(visitor.graph, "main", function):
            print(f"{cve}: Função Alcançável. Necessário Análise de Explorabilidade")
      else:
            print(f"{cve}: Não afeta o produto")

            