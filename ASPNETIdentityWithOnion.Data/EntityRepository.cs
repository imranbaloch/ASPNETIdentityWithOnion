using System;
using System.Collections.Generic;
using System.Data.Entity;
using System.Linq;
using System.Linq.Expressions;
using System.Threading.Tasks;
using ASPNETIdentityWithOnion.Core.Data;
using ASPNETIdentityWithOnion.Core.DomainModels;
using ASPNETIdentityWithOnion.Core.Extensions;

namespace ASPNETIdentityWithOnion.Data
{
    public class EntityRepository<TEntity> : IRepository<TEntity> where TEntity : BaseEntity
    {
        private readonly IEntitiesContext _context;
        private readonly IDbSet<TEntity> _dbEntitySet;
        private bool _disposed;

        public EntityRepository(IEntitiesContext context)
        {
            _context = context;
            _dbEntitySet = _context.Set<TEntity>();
        }

        public List<TEntity> GetAll()
        {
            return _dbEntitySet.ToList();
        }

        public PaginatedList<TEntity> GetAll(int pageIndex, int pageSize)
        {
            return GetAll(pageIndex, pageSize, x => x.Id);
        }

        public PaginatedList<TEntity> GetAll(int pageIndex, int pageSize, Expression<Func<TEntity, int>> keySelector, OrderBy orderBy = OrderBy.Ascending)
        {
            return GetAll(pageIndex, pageSize, keySelector, null, orderBy);
        }

        public PaginatedList<TEntity> GetAll(int pageIndex, int pageSize, Expression<Func<TEntity, int>> keySelector, Expression<Func<TEntity, bool>> predicate, OrderBy orderBy, params Expression<Func<TEntity, object>>[] includeProperties)
        {
            var entities = FilterQuery(keySelector, predicate, orderBy, includeProperties);
            var total = entities.Count();// entities.Count() is different than pageSize
            entities = entities.Paginate(pageIndex, pageSize);
            return entities.ToPaginatedList(pageIndex, pageSize, total);
        }

        public List<TEntity> GetAllIncluding(params Expression<Func<TEntity, object>>[] includeProperties)
        {
            var entities = IncludeProperties(includeProperties);
            return entities.ToList();
        }

        public TEntity GetSingle(int id)
        {
            return _dbEntitySet.FirstOrDefault(t => t.Id == id);
        }

        public TEntity GetSingleIncluding(int id, params Expression<Func<TEntity, object>>[] includeProperties)
        {
            var entities = IncludeProperties(includeProperties);
            return entities.FirstOrDefault(x => x.Id == id);
        }

        public List<TEntity> FindBy(Expression<Func<TEntity, bool>> predicate)
        {
            return _dbEntitySet.Where(predicate).ToList();
        }

        public void Insert(TEntity entity)
        {
            _context.SetAsAdded(entity);
        }

        public void Update(TEntity entity)
        {
            _context.SetAsModified(entity);
        }

        public void Delete(TEntity entity)
        {
            _context.SetAsDeleted(entity);
        }

        public Task<List<TEntity>> GetAllAsync()
        {
            return _dbEntitySet.ToListAsync();
        }

        public Task<PaginatedList<TEntity>> GetAllAsync(int pageIndex, int pageSize)
        {
            return GetAllAsync(pageIndex, pageSize, x => x.Id);
        }

        public Task<PaginatedList<TEntity>> GetAllAsync(int pageIndex, int pageSize, Expression<Func<TEntity, int>> keySelector, OrderBy orderBy = OrderBy.Ascending)
        {
            return GetAllAsync(pageIndex, pageSize, keySelector, null, orderBy);
        }

        public async Task<PaginatedList<TEntity>> GetAllAsync(int pageIndex, int pageSize, Expression<Func<TEntity, int>> keySelector,
            Expression<Func<TEntity, bool>> predicate, OrderBy orderBy, params Expression<Func<TEntity, object>>[] includeProperties)
        {
            var entities = FilterQuery(keySelector, predicate, orderBy, includeProperties);
            var total = await entities.CountAsync();// entities.CountAsync() is different than pageSize
            entities = entities.Paginate(pageIndex, pageSize);
            var list = await entities.ToListAsync();
            return list.ToPaginatedList(pageIndex, pageSize, total);
        }

        public Task<List<TEntity>> GetAllIncludingAsync(params Expression<Func<TEntity, object>>[] includeProperties)
        {
            var entities = IncludeProperties(includeProperties);
            return entities.ToListAsync();
        }

        public Task<TEntity> GetSingleAsync(int id)
        {
            return _dbEntitySet.FirstOrDefaultAsync(t => t.Id == id);
        }

        public Task<TEntity> GetSingleIncludingAsync(int id, params Expression<Func<TEntity, object>>[] includeProperties)
        {
            var entities = IncludeProperties(includeProperties);
            return entities.FirstOrDefaultAsync(x => x.Id == id);
        }

        public Task<List<TEntity>> FindByAsync(Expression<Func<TEntity, bool>> predicate)
        {
            return _dbEntitySet.Where(predicate).ToListAsync();
        }
        
        private IQueryable<TEntity> FilterQuery(Expression<Func<TEntity, int>> keySelector, Expression<Func<TEntity, bool>> predicate, OrderBy orderBy,
            Expression<Func<TEntity, object>>[] includeProperties)
        {
            var entities = IncludeProperties(includeProperties);
            entities = (predicate != null) ? entities.Where(predicate) : entities;
            entities = (orderBy == OrderBy.Ascending)
                ? entities.OrderBy(keySelector)
                : entities.OrderByDescending(keySelector);
            return entities;
        }

        private IQueryable<TEntity> IncludeProperties(params Expression<Func<TEntity, object>>[] includeProperties)
        {
            IQueryable<TEntity> entities = _dbEntitySet;
            foreach (var includeProperty in includeProperties)
            {
                entities = entities.Include(includeProperty);
            }
            return entities;
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        public virtual void Dispose(bool disposing)
        {
            if (!_disposed && disposing)
            {
                _context.Dispose();
            }
            _disposed = true;
        }
    }
}
